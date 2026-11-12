@ansible
Feature: Sudo under maximum security

  In maximum security the deployment hands sudo to the portal: its PAM stack
  only accepts a token the portal minted, and /etc/sudoers.d/open-bastion
  grants everything to the group that stack fills. The pam-access sudo rule
  of a server group decides who may elevate, and a drop-in an operator adds
  after that rule narrows what those users may run.

  Background:
    Given the fleet "two-backends" is ready
    And the LLNG configuration is "lmConf-with-plugins-configured"
    And the administrator generates the playbook with the "ob-builder-max-security" configuration
    And the administrator plays the generated playbook against the fleet
    Then the pam-access sudo rules are
      """
      backend: $uid eq "rtyler"
      bastion: 0
      """

  Scenario Outline: Sudo on the backends follows the rules of the portal
    Given user <name> has signed its SSH public key
    And user <name> has a temporary token from the portal
    When user <name> runs sudo on "backend-2" from "bastion-1" through SSH
    Then the result is <result>

    Examples:
      | name   | result  |
      | rtyler | success |
      | dwho   | fails   |

  Scenario: A NOPASSWD drop-in does not let sudo skip the portal
    Given user "rtyler" has signed its SSH public key
    And user "rtyler" has a temporary token from the portal
    And user "rtyler" writes the sudoers file "/etc/sudoers.d/zz-msmith" on "backend-2" from "bastion-1"
      """
      msmith ALL=(root) NOPASSWD: /usr/bin/id
      """
    Given user "msmith" has signed its SSH public key
    And user "msmith" has a temporary token from the portal
    When user "msmith" runs with sudo on "backend-2" from "bastion-1" through SSH
      """
      id
      """
    Then the result is fails

  Scenario: A NOPASSWD drop-in drops the token prompt
    Given user "rtyler" has signed its SSH public key
    And user "rtyler" has a temporary token from the portal
    And user "rtyler" writes the sudoers file "/etc/sudoers.d/zz-rtyler" on "backend-2" from "bastion-1"
      """
      rtyler ALL=(root) NOPASSWD: ALL
      """
    When user "rtyler" drops its cached sudo on "backend-2" from "bastion-1" through SSH
    When user "rtyler" runs with sudo, without a token, on "backend-2" from "bastion-1" through SSH
      """
      id
      """
    Then the result is success

  Scenario: An SSO user privileges can be limited
    Given user "rtyler" has signed its SSH public key
    And user "rtyler" has a temporary token from the portal
    And user "rtyler" writes the sudoers file "/etc/sudoers.d/zz-dwho" on "backend-2" from "bastion-1"
      """
      Defaults:dwho timestamp_timeout=0
      dwho ALL=(root) !ALL, /usr/bin/apt, /usr/bin/apt-get
      """
    And the administrator set pam-access sudo rule to:
      | backend | $uid eq "dwho" |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    Given user "dwho" has signed its SSH public key
    And user "dwho" has a temporary token from the portal
    When user "dwho" runs with sudo on "backend-2" from "bastion-1" through SSH
      """
      apt-get --version
      """
    Then the result is success
    Given user "dwho" has a temporary token from the portal
    When user "dwho" runs with sudo on "backend-2" from "bastion-1" through SSH
      """
      id
      """
    Then the result is fails
    And the refusal comes from the sudoers policy

  Scenario: A user allowed to sudo on the backends can't sudo on the bastion
    Given user "rtyler" has signed its SSH public key
    And user "rtyler" has a temporary token from the portal
    When user "rtyler" runs sudo on "bastion-1" through SSH
    Then the result is fails

  Scenario: A user the portal allows elevates on the bastion
    Given user "rtyler" has signed its SSH public key
    And user "rtyler" has a temporary token from the portal
    And the administrator set pam-access sudo rule to:
      | bastion | $uid eq "rtyler" |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    When user "rtyler" runs with sudo on "bastion-1" through SSH
      """
      id
      """
    Then the result is success

  Scenario: A user whose sudo access is removed can't sudo
    Given user "rtyler" has signed its SSH public key
    And user "rtyler" has a temporary token from the portal
    And the administrator set pam-access sudo rule to:
      | backend | 0 |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    When user "rtyler" runs sudo on "backend-2" from "bastion-1" through SSH
    Then the result is fails

  Scenario: A service account reach the bastion but can't sudo
    When service account "maintainer" tries to connect to "bastion-1" through SSH
    Then the result is success
    When service account "maintainer" runs sudo on "bastion-1" through SSH
    Then the result is fails

  Scenario: A service account reach the backends but can't sudo
    When service account "maintainer" tries to connect to "backend-1" through SSH
    Then the result is success
    When service account "maintainer" runs sudo on "backend-1" through SSH
    Then the result is fails

  Scenario: A service account added to the sudo group still can't sudo
    Given the administrator added "maintainer" to the group "open-bastion-sudo" of "backend-1"
    When service account "maintainer" runs sudo on "backend-1" through SSH
    Then the result is fails
    And the refusal comes from the password stage
