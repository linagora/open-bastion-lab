Feature: Ansible playbook for maximum security

  The playbook an administrator builds with ob-builder installs open-bastion on
  the fleet and enrols it against the portal. Users then reach the bastions
  with a certificate the portal signed, and the backends by hopping from a
  bastion, which vouches for them.

  # pshark copies its key before the machines are configured, while it can
  # still log in with the trivial password the fleet gives its accounts.
  Background:
    Given the fleet "two-backends" is ready
    And the LLNG configuration is "lmConf-with-plugins-configured"
    And user "pshark" has copied its SSH public key to "bastion-1"
    And user "pshark" has copied its SSH public key to "backend-2"
    And an administrator runs ob-builder to generate an ansible playbook with the "ob-builder-max-security" configuration
    And the administrator plays the generated playbook against the fleet

  Scenario Outline: Users known to the portal reach the bastion
    Given user <name> has signed its SSH public key
    When user <name> tries to connect to "bastion-1" through SSH
    Then the result is <result>

    Examples:
      | name   | result  |
      | dwho   | success |
      | rtyler | success |
      | msmith | success |

  Scenario Outline: Users known to the portal reach the backend through a bastion
    Given user <name> has signed its SSH public key
    When user <name> hops from "bastion-1" to "backend-2" through SSH
    Then the result is <result>

    Examples:
      | name   | result  |
      | dwho   | success |
      | rtyler | success |
      | msmith | success |

  Scenario: Users not known to the portal can't access the bastion
    When user "pshark" tries to connect to "bastion-1" through SSH
    Then the result is fails

  Scenario: Users not known to the portal can't access the backend
    When user "pshark" tries to connect to "backend-2" through SSH
    Then the result is fails

  Scenario: A user whose access to the backends is removed can't hop
    Given user "msmith" has signed its SSH public key
    And the administrator set pam-access SSH rule to:
      | backend | $uid eq "dwho" or $uid eq "rtyler" |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    When user "msmith" hops from "bastion-1" to "backend-2" through SSH
    Then the result is fails

  Scenario: A user whose access is removed can't reach the bastion
    Given user "rtyler" has signed its SSH public key
    And the administrator set pam-access SSH rule to:
      | bastion | $uid eq "dwho" or $uid eq "msmith" |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    When user "rtyler" tries to connect to "bastion-1" through SSH
    Then the result is fails

  Scenario Outline: Sudo on the backends follows the rules of the portal
    Given user <name> has signed its SSH public key
    And user <name> has a temporary token from the portal
    When user <name> runs sudo on "backend-2" from "bastion-1" through SSH
    Then the result is <result>

    Examples:
      | name   | result  |
      | rtyler | success |
      | dwho   | fails   |

  Scenario: A user allowed to sudo on the backends can't sudo on the bastion
    Given user "rtyler" has signed its SSH public key
    And user "rtyler" has a temporary token from the portal
    When user "rtyler" runs sudo on "bastion-1" through SSH
    Then the result is fails

  Scenario: A user whose sudo access is removed can't sudo
    Given user "rtyler" has signed its SSH public key
    And user "rtyler" has a temporary token from the portal
    And the administrator set pam-access sudo rule to:
      | backend | 0 |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    When user "rtyler" runs sudo on "backend-2" from "bastion-1" through SSH
    Then the result is fails

  # What the deployment left behind, read with the guest agent of the
  # machines: a configured fleet has no local account left that can
  # elevate, so these cannot be checked over SSH.
  Scenario: The bastion serves the service-account keys
    Then the bastion "bastion-1" serves the service-account keys

  Scenario: Sudo on the bastion goes through the portal
    Then the sudo stack of "bastion-1" asks the portal

  Scenario: The backends only accept the bastion of the fleet
    Then the backends accept only the bastion "bastion-1"
