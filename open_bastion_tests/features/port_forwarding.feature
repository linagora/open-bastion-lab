@ansible
Feature: Port forwarding through the bastion

  A user can ask a bastion to open a channel to a port of another machine:
  that is what ``ssh -L`` forwards a local port through, what ``ssh -W``
  writes a request through, and what a ProxyJump rides to reach a backend.

  The bastion dials the port the user names and relays what the channel
  carries, and the deployment leaves it at that: sshd permits TCP
  forwarding by default, no certificate option restricts it, and a
  forwarded channel is not a session, so session recording holds nothing
  of it. The portal rule the user passes to open a session is the only
  control on the way — the login behind the channel is what it authorizes
  and what it audits..

  Background:
    Given the fleet "two-backends" is ready
    And the LLNG configuration is "lmConf-with-plugins-configured"
    And the administrator generates the playbook with the "ob-builder-max-security" configuration
    And the administrator plays the generated playbook against the fleet
    Then the pam-access ssh rules are
      """
      bastion: $uid eq "dwho" or $uid eq "rtyler" or $uid eq "msmith"
      backend: $uid eq "dwho" or $uid eq "rtyler" or $uid eq "msmith"
      """

  Scenario: An SSO user reaches a port of a backend through a forwarded channel
    Given the administrator serves "ob-lab-forwarded" on port "8080" of "backend-2"
    And user "msmith" has signed its SSH public key
    When user "msmith" forwards port "8080" of "backend-2" through "bastion-1"
    Then the result is success
    And the forwarded port answers "ob-lab-forwarded"
    # The channel is not a session: what it carried is nowhere on the bastion.
    And "bastion-1" holds no recording of "msmith"

  Scenario: An SSO user cannot reach a backend through the bastion with ProxyJump
    Given user "msmith" has signed its SSH public key
    # The certificate the user presents to the backend is this one, and the
    # bastion accepts it: what the backend turns down is the hop itself.
    When user "msmith" tries to connect to "bastion-1" through SSH
    Then the result is success
    When user "msmith" tries to connect to "backend-2" through "bastion-1" with SSH ProxyJump
    Then the result is fails
    And "backend-2" refused the certificate of "msmith"

  Scenario: A bastion that refuses TCP forwarding refuses the channel
    Given user "msmith" has signed its SSH public key
    And the administrator closes TCP forwarding on "bastion-1"
    When user "msmith" forwards port "8080" of "backend-2" through "bastion-1"
    Then the result is fails
    And the refusal comes from the forwarding policy
