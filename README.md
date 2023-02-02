# Tcp-server protected from syn-flood(ddos) attacks
Basic idea was taken from [the publication]( https://www.csc.kth.se/utbildning/kth/kurser/DD143X/dkand12/Group5Mikael/final/Jonatan_Landsberg_and_Anton_Lundqvist.pdf)
# Glossary

## DDOS

A DDoS attack, which stands for “distributed denial-of-service” is a malicious attempt to disrupt the normal traffic of a targeted server, service or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic.

### [TCP Connection Attacks](https://blog.radware.com/security/2019/11/threat-alert-tcp-reflection-attacks/)

These attempt to use up all the available connections to infrastructure devices such as load-balancers, firewalls and application servers. Even devices capable of maintaining state on millions of connections can be taken down by these attacks.

## [Proof of work](https://en.wikipedia.org/wiki/Proof_of_work)

# Run in docker
## Server
### Server build
```
docker build -f ./docker/server/Dockerfile -t 'server:02022023' .
```
### Server run
```
docker run  --privileged --net host server:02022023
```
it's impossible to run the server using bpf without the flag
[issue](https://github.com/falcosecurity/falco/issues/1299)

## Client
### Client build
```
docker build -f ./docker/client/Dockerfile -t 'client:02022023' .
```
### Client run

```
docker run --net host --env CHALLENGE_ADDRESS=localhost:1053 --env DEST=localhost:5051 client:02022023```