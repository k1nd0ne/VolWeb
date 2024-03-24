<h1 align="center">
  <img src="https://github.com/k1nd0ne/VolWeb/assets/27780432/2c4cec14-b73c-4264-9936-215ca23a55d8" width="200" height="300" alt="VolWeb">
</h1>


# Introduction

VolWeb is a digital forensic memory analysis platform that leverages the power of the Volatility 3 framework. It is dedicated to aiding in investigations and incident responses.

![image](https://github.com/k1nd0ne/VolWeb/assets/27780432/691f1717-6c37-4147-9cac-e1a52aa2d1d0)

## Objective

The goal of VolWeb is to enhance the efficiency of memory collection and forensic analysis by providing a centralized, visual, and enhanced web application for incident responders and digital forensics investigators.
Once an investigator obtains a memory image from a Linux or Windows system, the evidence can be uploaded to VolWeb, which triggers automatic processing and extraction of artifacts using the power of the Volatility 3 framework.

By utilizing cloud-native storage technologies, VolWeb also enables incident responders to directly upload memory images into the VolWeb platform from various locations using dedicated scripts interfaced with the platform and maintained by the community. Another goal is to allow users to compile technical information, such as Indicators, which can later be imported into modern CTI platforms like OpenCTI, thereby connecting your incident response and CTI teams after your investigation.

# Project Documentation and Getting Started Guide

The project documentation is available on the <a href="https://github.com/k1nd0ne/VolWeb/wiki/VolWeb-Documentation">Wiki</a>. There, you will be able to deploy the tool in your investigation environment or lab.

>[!IMPORTANT]
> Take time to read the documentation in order to avoid miss configuration issues.


# Interacting with the REST API

VolWeb exposes a REST API to allow analysts to interact with the platform. There is a dedicated repository proposing some scripts maintained by the community: https://github.com/forensicxlab/VolWeb-Scripts

# Issues

If you have encountered a bug, or wish to propose a feature, please feel free to open an issue. To enable us to quickly address them, follow the guide in the "Contributing" section of the Wiki associated with the project.

# Contact

Contact me at k1nd0ne@mail.com for any questions regarding this tool.

# Next Release Goals

Check out the roadmap: https://github.com/k1nd0ne/VolWeb/projects/1
