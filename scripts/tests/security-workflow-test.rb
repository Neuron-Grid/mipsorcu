require 'minitest/autorun'
require 'open3'
require 'tmpdir'
require 'yaml'

class SecurityWorkflowTest < Minitest::Test
  WORKFLOW = File.expand_path('../../.github/workflows/ci.yml', __dir__)

  def run_security(deny: 0, vet: 0, install_deny: 0, install_vet: 0, toolchain: 0, checkout: 0)
    job = YAML.safe_load_file(WORKFLOW).fetch('jobs').fetch('security')
    refute job.key?('continue-on-error')
    Dir.mktmpdir do |dir|
      bin = File.join(dir, 'bin')
      Dir.mkdir(bin)
      File.write(File.join(bin, 'rustup'), "#!/bin/sh\nexit \"$TOOLCHAIN_EXIT\"\n")
      File.write(File.join(bin, 'cargo'), <<~'SH')
        #!/bin/sh
        case "$1 $3" in
          'install cargo-deny') exit "$INSTALL_DENY_EXIT" ;;
          'install cargo-vet') exit "$INSTALL_VET_EXIT" ;;
        esac
        case "$1" in
          deny) echo 'cargo-deny ran'; exit "$DENY_EXIT" ;;
          vet) echo 'cargo-vet ran'; exit "$VET_EXIT" ;;
          *) exit 99 ;;
        esac
      SH
      File.chmod(0o755, File.join(bin, 'cargo'), File.join(bin, 'rustup'))
      summary = File.join(dir, 'summary')
      env = {
        'PATH' => "#{bin}:#{ENV.fetch('PATH')}", 'GITHUB_STEP_SUMMARY' => summary,
        'DENY_EXIT' => deny.to_s, 'VET_EXIT' => vet.to_s,
        'INSTALL_DENY_EXIT' => install_deny.to_s, 'INSTALL_VET_EXIT' => install_vet.to_s,
        'TOOLCHAIN_EXIT' => toolchain.to_s
      }
      outcomes = {}
      logs = +''
      failed = false
      job.fetch('steps').each do |step|
        refute step.key?('continue-on-error')
        id = step['id']
        condition = step['if']
        if condition
          # Evaluate the supported workflow conditions; reject new expressions explicitly.
          terms = condition.delete_prefix('${{').delete_suffix('}}').strip.split(/\s*&&\s*/)
          enabled = terms.all? do |term|
            if term == 'always()'
              true
            elsif (match = /\Asteps\.(\w+)\.outcome == 'success'\z/.match(term))
              outcomes[match[1]] == 'success'
            else
              flunk "Unsupported workflow condition: #{term}"
            end
          end
          enabled &&= !failed unless terms.include?('always()')
        else
          enabled = !failed
        end
        unless enabled
          outcomes[id] = 'skipped' if id
          next
        end
        if step.key?('uses')
          outcomes[id] = checkout.zero? ? 'success' : 'failure' if id
          failed ||= !checkout.zero?
          next
        end
        step_env = step.fetch('env', {}).transform_values do |value|
          match = /\A\$\{\{ steps\.(\w+)\.outcome \}\}\z/.match(value)
          flunk "Unsupported workflow environment value: #{value}" unless match
          outcomes.fetch(match[1], '')
        end
        output, status = Open3.capture2e(env.merge(step_env), 'bash', '-e', '-c', step.fetch('run'))
        logs << output
        outcome = status.success? ? 'success' : 'failure'
        outcomes[id] = outcome if id
        failed ||= !status.success?
      end
      [failed ? 'failure' : 'success', outcomes, logs, File.read(summary)]
    end
  end

  def test_independent_checks_and_summary
    [
      [0, 0, 'success'], [1, 0, 'failure'], [0, 1, 'failure'],
      [1, 1, 'failure'], [127, 0, 'failure'], [0, 127, 'failure']
    ].each do |deny, vet, expected|
      result, outcomes, logs, summary = run_security(deny: deny, vet: vet)
      assert_equal expected, result
      assert_equal(deny.zero? ? 'success' : 'failure', outcomes.fetch('deny'))
      assert_equal(vet.zero? ? 'success' : 'failure', outcomes.fetch('vet'))
      assert_includes logs, 'cargo-deny ran'
      assert_includes logs, 'cargo-vet ran'
      assert_includes summary, "cargo-deny installation: success; check: #{outcomes.fetch('deny')}"
      assert_includes summary, "cargo-vet installation: success; check: #{outcomes.fetch('vet')}"
    end
  end

  def test_installation_failure_skips_only_its_check
    %i[install_deny install_vet].each do |failed_install|
      result, outcomes, logs, summary = run_security(**{ failed_install => 1 })
      assert_equal 'failure', result
      name = failed_install == :install_deny ? 'deny' : 'vet'
      other = name == 'deny' ? 'vet' : 'deny'
      assert_equal 'skipped', outcomes.fetch(name)
      assert_equal 'success', outcomes.fetch(other)
      refute_includes logs, "cargo-#{name} ran"
      assert_includes logs, "cargo-#{other} ran"
      assert_includes summary, "cargo-#{name} installation: failure; check: skipped"
    end
  end

  def test_toolchain_failure_skips_both_checks
    result, outcomes, logs, summary = run_security(toolchain: 1)
    assert_equal 'failure', result
    assert_equal 'skipped', outcomes.fetch('deny')
    assert_equal 'skipped', outcomes.fetch('vet')
    refute_includes logs, 'cargo-deny ran'
    refute_includes logs, 'cargo-vet ran'
    assert_includes summary, 'toolchain: failure'
    assert_includes summary, 'cargo-deny installation: skipped; check: skipped'
    assert_includes summary, 'cargo-vet installation: skipped; check: skipped'
  end

  def test_checkout_failure_skips_both_checks
    result, outcomes, logs, summary = run_security(checkout: 1)
    assert_equal 'failure', result
    assert_equal 'skipped', outcomes.fetch('deny')
    assert_equal 'skipped', outcomes.fetch('vet')
    refute_includes logs, 'cargo-deny ran'
    refute_includes logs, 'cargo-vet ran'
    assert_includes summary, 'Checkout: failure; toolchain: skipped'
    assert_includes summary, 'cargo-deny installation: skipped; check: skipped'
    assert_includes summary, 'cargo-vet installation: skipped; check: skipped'
  end
end
