@installer
Feature: The self-extracting installers for maximum security

  ob-builder writes one self-extracting installer per role, with
  --output-shell. An administrator copies each to its target and runs it as
  root: the installer writes the configuration, installs open-bastion, enrols
  the host against the portal and locks it down, so the fleet ends up where
  the playbook deployment leaves it. The bastion is deployed first, because
  its id is what the backends allow; the backend installer is built with it.

  Background:
    Given the fleet "two-backends" is ready
    And the LLNG configuration is "lmConf-with-plugins-configured"
    And user "pshark" has copied its SSH public key to "bastion-1"
    And user "pshark" has copied its SSH public key to "backend-2"
    And the administrator generates the installer of the bastion with the "ob-builder-max-security" configuration
    And the administrator runs the installer on "bastion-1"
    And the administrator approves the enrolment of "bastion-1"
    And the installer of "bastion-1" succeeded
    And the administrator generates the installer of the backends allowing the bastion "bastion-1"
    And the administrator runs the installer on "backend-1"
    And the administrator approves the enrolment of "backend-1"
    And the installer of "backend-1" succeeded
    And the administrator runs the installer on "backend-2"
    And the administrator approves the enrolment of "backend-2"
    And the installer of "backend-2" succeeded
    Then the pam-access ssh rules are
      """
      bastion: $uid eq "dwho" or $uid eq "rtyler" or $uid eq "msmith"
      backend: $uid eq "dwho" or $uid eq "rtyler" or $uid eq "msmith"
      """
    And the pam-access sudo rules are
      """
      backend: $uid eq "rtyler"
      bastion: 0
      """

  Scenario Outline: SSO users reach the bastion
    Given user <name> has signed its SSH public key
    When user <name> tries to connect to "bastion-1" through SSH
    Then the result is <result>

    Examples:
      | name   | result  |
      | dwho   | success |
      | rtyler | success |
      | msmith | success |

  Scenario Outline: SSO users reach the backend through a bastion
    Given user <name> has signed its SSH public key
    When user <name> hops from "bastion-1" to "backend-2" through SSH
    Then the result is <result>

    Examples:
      | name   | result  |
      | dwho   | success |
      | rtyler | success |
      | msmith | success |

  Scenario: Non-SSO users can't access the bastion
    # pshark copied its key before the machines are configured, while
    # it can still log in with the trivial password the fleet gives
    # its accounts.
    When user "pshark" tries to connect to "bastion-1" through SSH
    Then the result is fails

  Scenario: Non-SSO users can't access the backend
    # pshark copied its key before the machines are configured, while
    # it can still log in with the trivial password the fleet gives
    # its accounts.
    When user "pshark" tries to connect to "backend-2" through SSH
    Then the result is fails

  Scenario: An SSO user whose access to the backends is removed can't hop
    Given user "msmith" has signed its SSH public key
    And the administrator set pam-access SSH rule to:
      | backend | $uid eq "dwho" or $uid eq "rtyler" |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    When user "msmith" hops from "bastion-1" to "backend-2" through SSH
    Then the result is fails

  Scenario: An SSO user whose access is removed can't reach the bastion
    Given user "rtyler" has signed its SSH public key
    And the administrator set pam-access SSH rule to:
      | bastion | $uid eq "dwho" or $uid eq "msmith" |
    And the portal workers reloaded the configuration
    And the administrator drops the authorization cache of the fleet
    When user "rtyler" tries to connect to "bastion-1" through SSH
    Then the result is fails

  Scenario: The backends only accept the bastion of the fleet
    Then the backends accept only the bastion "bastion-1"

  # What the stack this deployment writes ensures — who may sudo, and that
  # the portal alone decides it — is exercised in sudo_maximum_security.feature.
  Scenario: Sudo on the bastion goes through the portal
    When the administrator reads "/etc/pam.d/sudo" on "bastion-1" as a stream
    Then a line matches the pattern
      """
      ^auth\s+sufficient\s+pam_openbastion\.so$
      """
    And a line matches the pattern
      """
      ^auth\s+required\s+pam_deny\.so$
      """

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

  Scenario: The bastion records what an SSO user does on a backend
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

  Scenario: The cache keeps an SSO user's access while the portal is down
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
