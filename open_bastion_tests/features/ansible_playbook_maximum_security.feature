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

  # The scenarios that change the rules of the portal come last: the feature
  # keeps the portal it was given, so the backend rule goes before the bastion
  # one, which takes away the access a hop needs.
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
