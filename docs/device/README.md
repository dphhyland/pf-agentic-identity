# The device path

What a device-resident agent and the enrolment service say to each other, written for the people who build the
device side. The service itself is [services/device-enrolment](../../services/device-enrolment/README.md); the
registry it writes is [libs/device-instance](../../libs/device-instance/README.md); the App Attest verification
it relies on is [libs/app-attest](../../libs/app-attest/README.md).

- [ios-client-contract.md](ios-client-contract.md) - every request the iOS client makes, in order, with its
  fields, where each value comes from on the device, the errors and what the client does on each, and what is
  not yet known. The reference client is [clients/ios](../../clients/ios/README.md).

A document here is written from the Java, cites it by file and symbol, and says which commit it was read at.
When the Java moves, the document is stale until someone reads it again.
