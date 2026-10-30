@ansible
Feature: Ansible playbook for maximum security

  The playbook an administrator builds with ob-builder installs open-bastion on
  the fleet and enrols it against the portal. Users then reach the bastions
  with a certificate the portal signed, and the backends by hopping from a
  bastion, which vouches for them.

  Background:
    Given the fleet "three-backends" is ready
    And the LLNG configuration is "lmConf-with-plugins-configured"
    And user "pshark" has copied its SSH public key to "bastion-1"
    And user "pshark" has copied its SSH public key to "backend-2"
    And the administrator generates the playbook with the "ob-builder-max-security" configuration
    And the administrator plays the generated playbook against the fleet, backend-3 excluded

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
    # pshark copied its key before the machines are configured, while
    # it can still log in with the trivial password the fleet gives
    # its accounts.
    When user "pshark" tries to connect to "bastion-1" through SSH
    Then the result is fails

  Scenario: Users not known to the portal can't access the backend
    # pshark copied its key before the machines are configured, while
    # it can still log in with the trivial password the fleet gives
    # its accounts.
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

  Scenario: Sudo on the bastion goes through the portal
    Then the sudo stack of "bastion-1" asks the portal

  Scenario: The backends only accept the bastion of the fleet
    Then the backends accept only the bastion "bastion-1"

  Scenario: SSO users can play a second playbook
    Given user "msmith" has signed its SSH public key
    And the administrator set pam-access sudo rule to:
      | bastion | $uid eq "msmith" |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    When the administrator plays the playbook again as "msmith" for "bastion-1"
    Then the play succeeds

  Scenario: Non-SSO users can't play a second playbook
    When the administrator plays the playbook again for "bastion-1" as a service account
    Then the play changed nothing on "bastion-1"
    And the play warns that "bastion-1" keeps its SSO sudo

  # The recap counts the setup task as changed whatever it does: it is what
  # applies an upgraded package, so what a replay did is read on the files
  # the setup wrote, and on the revocation list it downloaded.
  Scenario: Playing the tree again as an SSO user leaves the configuration alone
    Given user "msmith" has signed its SSH public key
    And the administrator set pam-access sudo rule to:
      | bastion | $uid eq "msmith" |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    And the administrator records the configuration of "bastion-1"
    When the administrator plays the playbook again as "msmith" for "bastion-1"
    Then the play succeeds
    When the administrator plays the playbook again as "msmith" for "bastion-1"
    Then the play succeeds
    And the configuration of "bastion-1" is unchanged
    And the revocation list of "bastion-1" holds what the portal revoked
    And the play warns that "bastion-1" keeps its SSO sudo

  Scenario: A revoked certificate is refused once the list is refreshed
    Given user "msmith" has signed its SSH public key
    When user "msmith" tries to connect to "bastion-1" through SSH
    Then the result is success
    Given user "rtyler" has signed its SSH public key
    Given the administrator revokes the certificate of "msmith"
    Given the administrator set pam-access sudo rule to:
      | bastion | $uid eq "rtyler" |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    Given user "rtyler" has a temporary token from the portal
    When user "rtyler" runs sudo "ob-krl-refresh" on "bastion-1" through SSH
    Then the result is success
    When user "msmith" tries to connect to "bastion-1" through SSH
    Then the result is fails
    Given user "msmith" has signed its SSH public key
    When user "msmith" tries to connect to "bastion-1" through SSH
    # no refresh needed that time, thanks to use of serials in KRL
    Then the result is success

  Scenario: The bastion records what a user does on a backend
    Given user "msmith" has signed its SSH public key
    When user "msmith" hops from "bastion-1" to "backend-1" through SSH and runs
      """
      echo first-command
      echo output-$((40+2))
      nohup sleep 60 >/dev/null 2>&1 & echo nohup-attempted
      """
    Then the result is success
    And the recording of "msmith" on "bastion-1" holds:
      | first-command   |
      | output-42       |
      | nohup-attempted |

  Scenario: The cache keeps a user's access while the portal is down
    Given user "rtyler" has signed its SSH public key
    When user "rtyler" tries to connect to "bastion-1" through SSH
    Then the result is success
    And the authorization of "rtyler" is cached on "bastion-1"
    When user "rtyler" hops from "bastion-1" to "backend-2" through SSH
    Then the result is success
    And the authorization of "rtyler" is cached on "backend-2"
    When the portal is down
    When user "rtyler" tries to connect to "bastion-1" through SSH
    Then the result is success
    When user "rtyler" hops from "bastion-1" to "backend-2" through SSH
    Then the hop cannot be made
    When the authorization of "rtyler" is removed from "bastion-1"
    When user "rtyler" tries to connect to "bastion-1" through SSH
    Then the result is fails
