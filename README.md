# PKU Pitfalls


### Requirements

- CPU must support Intel PKU. This includes Skylake Server architectures chips e.g. Xeon Scalable series.
    - Note: Amazon's EC2 `c5.large` instance offers an easy way to access a PKU-caapable CPU.
- Linux kernel >= 4.9.0, compiled with PKU support enabled (e.g. recent Ubuntu or Debian).
- docker

### Running

Build the docker image using the provided script:

```
./build.sh
```

Building the image also compiles all of the necessary components including ERIM itself and the PoCs.

Run the docker image:

```
./run.sh
```

The image will automatically run each PoC. Each PoC uses a common library called secure\_lib. secure\_lib is a minimal example of a library that allocates and uses isolated memory to protect a secret (the secret is in fact the hardcoded string `S0_5ecr3T`). Each PoC attempts to access the isolated memory without using a legitimate call gate. A successful PoC will access the secret and then print it out in the following format:

```
TRYING TO STEAL THE SECRET: S0_5ecr3T
```

This output indicates that the exploit succeeded and the untrusted component was able to access the protected memory without using a legitimate call gate.
Most of the PoCs should be very quick with the exception of scan\_race, which may take several minutes to run as it adjusts and tries different timing configuration.


 ### Project Structure

- The `erim/` directory contains the original ERIM source code, with some changes to improve support for the ptrace-based sandbox.
- pku\_exploits/ contains proof-of-concepts for several attacks.
    - The code for each PoC lives in pku\_exploits/exploits/
    - All PoCs can be tested by running `make test` in pku\_exploits/

