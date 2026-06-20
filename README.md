# Secure E-Voting System

## Project Overview
Secure online e-voting system with support for organizers and voters, designed to ensure confidentiality, integrity, and authentication using cryptographic techniques and PKI infrastructure.

## Features
- User registration with automatic certificate and key generation
- Two-step authentication (certificate + credentials)
- Organizer role for creating and managing elections
- Voter role for participating in elections
- Secure vote encryption and digital signatures
- Vote verification without revealing content
- Automatic vote counting after election ends

## Security
- PKI hierarchy (Root CA + issuing CAs)
- RSA for key exchange
- AES for vote encryption
- HMAC for integrity protection
- Digital signatures for authentication

## Result
- Secure election management
- Encrypted and verifiable voting process
