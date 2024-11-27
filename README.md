<h1 align="center">
  <img src="https://github.com/k1nd0ne/VolWeb/assets/27780432/2c4cec14-b73c-4264-9936-215ca23a55d8" width="400" height="200" alt="VolWeb">
</h1>


# Introduction

VolWeb is a digital forensic memory analysis platform that leverages the power of the Volatility 3 framework.
It is dedicated to aiding in investigations and incident responses.



## Objectives

The goal of VolWeb is to enhance the efficiency of memory collection and forensic analysis by providing a centralized, visual, and enhanced web application for incident responders and digital forensics investigators.
Once an investigator obtains a memory image from a Linux or Windows system (Mac coming soon), the evidence can be uploaded to VolWeb, which triggers automatic processing and extraction of artifacts using the power of the Volatility 3 framework.

By utilizing hybrid storage technologies, VolWeb also enables incident responders to directly upload memory images into the VolWeb platform from various locations using dedicated scripts interfaced with the platform and maintained by the community.
Another goal is to allow users to compile technical information, such as Indicators, which can later be imported into modern CTI platforms like OpenCTI, thereby connecting your incident response and CTI teams after your investigation.

# Project Documentation and Getting Started Guide

The project documentation is available on the <a href="https://github.com/k1nd0ne/VolWeb/wiki/VolWeb-Documentation">Wiki</a>.
There, you will be able to deploy the tool in your investigation environment or lab.

>[!IMPORTANT]
> Take time to read the documentation in order to avoid common miss-configuration issues.

# Analysis features
A quick disclaimer: VolWeb is meant to be use in conjunction with the volatility3 framework CLI,
it offers a different way to review & investigate some of the results and will not do all of the deep dive analysis job for you.

## Investigate

The investigate feature is one of the core feature of VolWeb.
It provides an overview of the available artefacts that were retrived by the custom volatiltiy3 engine in the backend.
If available, you can visualize the process tree and get basic information about each process, dump them etc...
You also get a enhanced view of all of the plugins results by categories.

<img width="1728" alt="image" src="https://github.com/user-attachments/assets/ecdc3ba5-e3e1-48b9-9e82-3d8bba1649ae">


## Explore
« _Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win._ »

The explore feature comes with VolWeb 3.0 for Windows investigations (coming soon for Linux).
It enable the memory forensics expert to investigate potential suspicious processes in a graph view allowing another way to look at the data, but also correlate the volatility3 plugins to get more context.

<img width="1728" alt="image" src="https://github.com/user-attachments/assets/e77e5c07-4ff7-4bdb-9eb4-d8880e0a0107">

## Capitalize and share indicators

When the expert found malicious activies, VolWeb give you the possibility to create STIX V2 Indicators directly from the interface and centralize them in your case.
Once your case is closed, you can generate you STIX bundle and share your Indicators with your community using CTI Platforms like MISP or OpenCTI.

<img width="1728" alt="image" src="https://github.com/user-attachments/assets/5e4015ff-5eeb-495b-bfe0-7fd3bcdfe43c">


## Interacting with the REST API

VolWeb exposes a REST API to allow analysts to interact with the platform. A swagger is available on the platform in oder to get the full documentation.
There is a dedicated repository proposing some scripts maintained by the community: https://github.com/forensicxlab/VolWeb-Scripts .

<img width="1728" alt="image" src="https://github.com/user-attachments/assets/84578c55-bba3-4695-b25e-bdb4e25c60bb">

## Administration

VolWeb is using django in the backend. Manage your user and database directly from the admin panel.

<img width="1718" alt="image" src="https://github.com/user-attachments/assets/ded4d50e-23ee-4154-bc22-0ddb76678495">

# Issues & Feature request

If you have encountered a bug, or wish to propose a feature, please feel free to create a [discussion](https://github.com/k1nd0ne/VolWeb/discussions) to enable us to quickly address them. Please provide logs to any issues you are facing.


# Contributing

VolWeb is open to contributions. Follow the contributing guideline to propose features.

# Contact

Contact me at k1nd0ne@mail.com for any questions regarding this tool.

# Next Release Goals

Check out the [roadmap](https://github.com/users/k1nd0ne/projects/2)

Check out the [discussions](https://github.com/k1nd0ne/VolWeb/discussions)
