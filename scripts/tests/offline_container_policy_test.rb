# frozen_string_literal: true

require 'minitest/autorun'
require 'open3'
require 'json'
require 'fileutils'
require 'tmpdir'
require 'timeout'

# Checks the container runner's output and PostgreSQL isolation guards.
class OfflineContainerPolicyTest < Minitest::Test
  SCRIPT = File.expand_path('../test-orchestrator-offline-container.sh', __dir__)
  SOURCE = File.read(SCRIPT)
  CAPTURE_FUNCTION = SOURCE[/^capture_bounded\(\) \{.*?^\}/m]
  DOCKER_CONTROL_FUNCTION = SOURCE[/^bounded_docker_control\(\) \{.*?^\}/m]
  POSTGRES_GUARD = SOURCE[/python3 - "\$postgres_host_config" <<'PY'\n(.*?)^PY$/m, 1]
  LIMIT = 4 * 1024 * 1024

  def test_capture_redacts_synthetic_secret
    output, _error, status = run_capture('prefix-secret-suffix', 'secret')

    assert status.success?
    assert_equal 'prefix-[REDACTED]-suffix', output
  end

  def test_capture_rejects_output_over_four_mib
    output, _error, status = run_capture('x' * (LIMIT + 1), '')

    refute status.success?
    assert_empty output
  end

  def test_capture_deadline_rejects_a_stream_that_never_closes
    command = "#{CAPTURE_FUNCTION}\ncapture_bounded '' 1"
    Open3.popen3('bash', '-c', command) do |input, _output, _error, wait|
      begin
        status = Timeout.timeout(5) { wait.value }
        refute status.success?
      ensure
        input.close
        begin
          Process.kill('KILL', wait.pid) if wait.alive?
        rescue Errno::ESRCH
          nil
        end
      end
    end
  end

  def test_bounded_docker_control_propagates_success_and_failure
    with_fake_docker do |directory|
      [0, 7].each do |exit_code|
        _output, _error, status = run_docker_control(directory, exit_code.to_s)

        assert_equal exit_code, status.exitstatus
      end
    end
  end

  def test_bounded_docker_control_kills_a_stalled_cli
    with_fake_docker do |directory|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      _output, _error, status = run_docker_control(directory, 'hang')
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

      assert_equal 124, status.exitstatus
      assert_operator elapsed, :<, 5
    end
  end

  def test_bounded_docker_control_rejects_zero_timeout
    with_fake_docker do |directory|
      _output, _error, status = run_docker_control(directory, '0', 0)

      assert_equal 125, status.exitstatus
    end
  end

  def test_bounded_docker_control_stops_its_child_on_termination
    with_fake_docker do |directory|
      pid_file = File.join(directory, 'pid')
      env = { 'PATH' => "#{directory}:#{ENV.fetch('PATH')}", 'TASK_FAKE_DOCKER_MODE' => 'hang',
              'TASK_FAKE_DOCKER_PIDFILE' => pid_file, 'task_docker_endpoint' => 'unix:///not-used' }
      command = "#{DOCKER_CONTROL_FUNCTION}\nbounded_docker_control 10 --exec"
      Open3.popen3(env, 'bash', '-c', command) do |input, _output, _error, wait|
        input.close
        begin
          Timeout.timeout(5) { sleep 0.02 until File.file?(pid_file) }
          child_pid = Integer(File.read(pid_file))
          Process.kill('TERM', wait.pid)
          assert_equal 143, Timeout.timeout(5) { wait.value }.exitstatus
          Timeout.timeout(5) do
            loop do
              begin
                Process.kill(0, child_pid)
              rescue Errno::ESRCH
                break
              end
              sleep 0.02
            end
          end
        ensure
          begin
            Process.kill('KILL', wait.pid) if wait.alive?
          rescue Errno::ESRCH
            nil
          end
        end
      end
    end
  end

  def test_postgres_guard_accepts_only_expected_host_limits
    _output, _error, status = run_postgres_guard(valid_host_config)

    assert status.success?
  end

  def test_postgres_guard_rejects_privileged_mode
    assert_guard_rejects(valid_host_config.merge('Privileged' => true))
  end

  def test_postgres_guard_rejects_host_mounts
    assert_guard_rejects(valid_host_config.merge('Binds' => ['/host:/container']))
  end

  def test_postgres_guard_rejects_resource_or_capability_changes
    assert_guard_rejects(valid_host_config.merge('Memory' => 1_073_741_824))
    cap_add = valid_host_config.fetch('CapAdd') + ['SYS_ADMIN']
    assert_guard_rejects(valid_host_config.merge('CapAdd' => cap_add))
  end

  private

  def run_capture(input, secret)
    raise 'capture_bounded function was not found' unless CAPTURE_FUNCTION

    command = "#{CAPTURE_FUNCTION}\ncapture_bounded \"$TASK_REDACT\""
    Open3.capture3({ 'TASK_REDACT' => secret }, 'bash', '-c', command, stdin_data: input)
  end

  def run_postgres_guard(config)
    raise 'PostgreSQL host config guard was not found' unless POSTGRES_GUARD

    Open3.capture3('python3', '-', JSON.generate(config), stdin_data: POSTGRES_GUARD)
  end

  def run_docker_control(directory, mode, timeout = 1)
    raise 'bounded Docker control function was not found' unless DOCKER_CONTROL_FUNCTION

    command = "#{DOCKER_CONTROL_FUNCTION}\nbounded_docker_control #{timeout}"
    Open3.capture3(
      { 'PATH' => "#{directory}:#{ENV.fetch('PATH')}", 'TASK_FAKE_DOCKER_MODE' => mode,
        'task_docker_endpoint' => 'unix:///not-used' },
      'bash', '-c', command
    )
  end

  def with_fake_docker
    Dir.mktmpdir('mipsorcu-fake-docker-') do |directory|
      docker = File.join(directory, 'docker')
      File.write(docker, <<~PYTHON)
        #!/usr/bin/env python3
        import os
        import signal
        import sys
        import time

        mode = os.environ['TASK_FAKE_DOCKER_MODE']
        pid_file = os.environ.get('TASK_FAKE_DOCKER_PIDFILE')
        if pid_file:
            temporary_pid_file = pid_file + '.tmp'
            with open(temporary_pid_file, 'w', encoding='ascii') as output:
                output.write(str(os.getpid()))
            os.replace(temporary_pid_file, pid_file)
        if mode == 'hang':
            signal.signal(signal.SIGALRM, signal.SIG_IGN)
            time.sleep(10)
        sys.exit(int(mode))
      PYTHON
      FileUtils.chmod(0o700, docker)
      yield directory
    end
  end

  def valid_host_config
    {
      'NanoCpus' => 1_000_000_000,
      'Memory' => 536_870_912,
      'PidsLimit' => 128,
      'Privileged' => false,
      'Binds' => [],
      'CapDrop' => ['ALL'],
      'CapAdd' => %w[CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID],
      'SecurityOpt' => ['no-new-privileges']
    }
  end

  def assert_guard_rejects(config)
    _output, _error, status = run_postgres_guard(config)
    refute status.success?, "unsafe host config passed: #{config.keys.join(', ')}"
  end
end
