Feature: Ansible playbook for maximum security with hardening

  The hardening of the deployment has the system clean up after a session:
  logind takes down the processes it started, so a command a user leaves
  running with nohup does not outlive it.

  Background:
    Given the fleet "two-backends" is ready
    And the LLNG configuration is "lmConf-with-plugins-configured"
    And the administrator generates the playbook with the "ob-builder-max-security-with-hardening" configuration
    And the administrator plays the generated playbook against the fleet

  Scenario: A command left running is recorded and does not outlive the session
    Given user "msmith" has signed its SSH public key
    When user "msmith" hops from "bastion-1" to "backend-1" through SSH and runs "nohup sleep 120 >/dev/null 2>&1 & echo started"
    Then the result is success
    And the recording of "msmith" on "bastion-1" holds:
      | started |
    And no process of "msmith" is left on "backend-1"
