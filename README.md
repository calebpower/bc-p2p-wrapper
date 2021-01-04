# Test driver for various Bouncy Castle algorithms.

This repository is really just a separate place for me to test some algorithmic implementations-- it's not intended to be directly included in any project.

## Build

This project requires Java 11 and has been successfully built and executed on FreeBSD, Windows, and several GNU/Linux flavors.

This project can be tested and compiled with the following command.

`gradlew clean shadowJar`

## Execution

To run it, just do `java -jar build/libs/bc-p2p-wrapper.jar`.
