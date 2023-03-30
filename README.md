# Simple-PKI

It has 5 main components: 
- RootCA
- CA
- Entity
- Certificate
- Verification_Authority

The software allows a hierarchical structure of certification authorities (CAs) not limited to the depth or number of authorities. A certification authority can also give permission to an ordinary entity, thus authorizing it to be registered as a certification itself.

\
A demo is shown in PKI.py for the cases in the following diagram:

![Tests_diagram](https://user-images.githubusercontent.com/58553700/228947603-7deb5e55-0b46-4b61-8646-5d3f6a785724.png)

Output of PKI.py:

![output](https://user-images.githubusercontent.com/58553700/228948300-f60b0027-910f-4a22-a149-42c286ffdc0e.png)
