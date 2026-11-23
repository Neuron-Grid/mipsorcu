require 'minitest/autorun'
require 'open3'
require 'yaml'

class SecurityWorkflowTest < Minitest::Test
  WORKFLOW = File.expand_path('../../.github/workflows/ci.yml', __dir__)
  REQUIRED_JOBS = %w[rust supabase orchestrator orchestrator_postgres cargo_deny cargo_vet e2e failure_injection validation_tests].freeze

  def workflow
    YAML.safe_load_file(WORKFLOW).fetch('jobs')
  end

  def test_required_checks_are_independent_jobs_without_skip_or_continue_on_error
    jobs = workflow
    REQUIRED_JOBS.each do |name|
      job = jobs.fetch(name)
      refute job.key?('continue-on-error'), "#{name} must not continue after failure"
      refute job.key?('if'), "#{name} must run without a conditional skip"
      job.fetch('steps').each do |step|
        refute step.key?('continue-on-error'), "#{name} step must not continue after failure"
      end
    end

    assert_includes jobs.fetch('rust').fetch('steps').map { |step| step['run'] }.compact,
                    'bash scripts/check-core.sh rust'
    assert_includes jobs.fetch('supabase').fetch('steps').map { |step| step['run'] }.compact,
                    'bash scripts/check-core.sh db'
    assert_includes jobs.fetch('orchestrator').fetch('steps').map { |step| step['run'] }.compact,
                    'cargo test --locked --manifest-path orchestrator/Cargo.toml'
    postgres_commands = jobs.fetch('orchestrator_postgres').fetch('steps').map { |step| step['run'] }.compact
    postgres_pull = 'docker pull postgres@sha256:a77aa70e641402a21411b92b721c58d10f23b50ae5fdd2333efd22d166e1e5f7'
    rust_pull = 'docker pull rust@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082'
    cargo_fetch = 'cargo fetch --locked --manifest-path orchestrator/Cargo.toml'
    isolated_test = 'bash scripts/test-orchestrator-offline-container.sh postgres-tests'
    [postgres_pull, rust_pull, cargo_fetch, isolated_test].each { |command| assert_includes postgres_commands, command }
    refute_includes postgres_commands, 'bash scripts/test-orchestrator-postgres.sh'
    [postgres_pull, rust_pull, cargo_fetch].each do |command|
      assert_operator postgres_commands.index(command), :<, postgres_commands.index(isolated_test)
    end
    assert_includes jobs.fetch('cargo_deny').fetch('steps').map { |step| step['run'] }.compact,
                    'cargo deny --locked check'
    vet_commands = jobs.fetch('cargo_vet').fetch('steps').map { |step| step['run'] }.compact
    assert_includes vet_commands, 'cargo vet --locked --no-minimize-exemptions'
    assert_includes vet_commands, 'python3 scripts/check-cargo-vet-exemptions.py'
    exemption_step = jobs.fetch('cargo_vet').fetch('steps').find do |step|
      step['run'] == 'python3 scripts/check-cargo-vet-exemptions.py'
    end
    assert_equal '${{ always() }}', exemption_step.fetch('if')
    validation_commands = jobs.fetch('validation_tests').fetch('steps').map { |step| step['run'] }.compact
    assert_includes validation_commands, 'python3 scripts/tests/test-cargo-vet-exemptions.py'
    assert_includes validation_commands, 'python3 scripts/tests/test_ci_policy.py'
    assert_includes validation_commands, 'bash scripts/tests/failure-injection-contract-test.sh'
    assert_includes validation_commands, 'ruby scripts/tests/security-workflow-test.rb'
    assert_includes validation_commands, 'ruby scripts/tests/offline_container_policy_test.rb'
    assert_includes validation_commands, 'python3 -B scripts/tests/test_receive_orchestrator_artifacts.py'
  end

  def test_e2e_and_failure_injection_fail_closed_until_isolated_runners_exist
    jobs = workflow
    assert_match(/exit 1/, jobs.fetch('e2e').fetch('steps').first.fetch('run'))
    assert_match(/exit 1/, jobs.fetch('failure_injection').fetch('steps').first.fetch('run'))
  end

  def test_aggregate_requires_every_job_and_runs_after_failures
    aggregate = workflow.fetch('required')
    assert_equal REQUIRED_JOBS, aggregate.fetch('needs')
    assert_equal '${{ always() }}', aggregate.fetch('if')

    env = aggregate.fetch('steps').first.fetch('env')
    REQUIRED_JOBS.each do |name|
      key = name.upcase.gsub(/[^A-Z0-9]/, '_') + '_RESULT'
      assert_equal "${{ needs.#{name}.result }}", env.fetch(key)
    end
  end

  def test_only_success_outcomes_pass_aggregate
    script = workflow.fetch('required').fetch('steps').first.fetch('run')
    success_env = REQUIRED_JOBS.to_h do |name|
      [name.upcase.gsub(/[^A-Z0-9]/, '_') + '_RESULT', 'success']
    end
    _output, status = Open3.capture2e(success_env, 'bash', '-e', '-c', script)
    assert status.success?

    REQUIRED_JOBS.each do |failed_job|
      %w[failure skipped cancelled neutral].each do |outcome|
        env = success_env.merge(
          failed_job.upcase.gsub(/[^A-Z0-9]/, '_') + '_RESULT' => outcome
        )
        _output, status = Open3.capture2e(env, 'bash', '-e', '-c', script)
        refute status.success?, "#{failed_job}=#{outcome} must fail aggregate"
      end
    end

    env = success_env.merge('CARGO_VET_RESULT' => '')
    _output, status = Open3.capture2e(env, 'bash', '-e', '-c', script)
    refute status.success?, 'missing outcome must fail aggregate'
  end
end
