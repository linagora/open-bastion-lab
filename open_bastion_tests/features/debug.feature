Feature: Configured lab for debugging

  # Run it with:
  #
  #   pytest -m debug

  Background:
    Given the fleet "two-backends" is ready
    And the LLNG configuration is "lmConf-with-plugins-configured"
    And user "pshark" has copied its SSH public key to "bastion-1"
    And user "pshark" has copied its SSH public key to "backend-2"
    And an administrator runs ob-builder to generate an ansible playbook with the "ob-builder-max-security" configuration
    And the administrator plays the generated playbook against the fleet

  Scenario: The lab is configured
    Then the run waits for a Ctrl-C
