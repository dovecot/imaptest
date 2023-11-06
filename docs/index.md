---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: ImapTest
  text: IMAP Server Tester
  tagline: ImapTest is a generic IMAP server compliancy tester that works with all IMAP servers
  image:
    src: ./test-icon.svg
    alt: ImapTest
  actions:
    - theme: brand
      text: Get Started
      link: /installation
    - theme: alt
      text: Configuration
      link: /configuration

features:
  - title: Stress Testing
    details: Stress testing with state tracking. ImapTest sends random commands to the server and verifies that server's output looks correct.
  - title: Scripted Testing
    details: Scripted testing to run a list of pre-defined scripted tests and verify the server returns expected output.
  - title: Benchmarking
    details: ImapTest returns performance results during testing, that can be used for benchmarking purposes.
---

