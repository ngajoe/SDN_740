# CloudLab Material Summary

[TOC]



### Teaching SDN Security Using Hands-on Labs in CloudLab

The paper was first found by Shichun. It uses Cloudlab to do SDN seurity labs.

The one that I choose as a reference is **Lab 11 SDN applications**.



Goal: I want to learn how to deploy things on Cloublab in this project.

Also I will focus on **Lab 1 Starting with CloudLab and Lab 2 Software Defined Networking**.



#### Website

I actually didn't find the exact course, but I found a [similar one](https://www.svcsi.org/sdnnfvlabs#lab1). 



#### Lab1 Starting with Cloudlab

This one teaches us how to create a topology.

- [x] Tested by me



#### Lab2 Software Defined Networking

This one teaches us how to set up a Ryu controller and build bridges on all nodes.

1. Set up a node => install Ryu => start controller

   There could be a problem: [Python locale error: unsupported locale setting](https://stackoverflow.com/questions/14547631/python-locale-error-unsupported-locale-setting)

   Solution: `export LC_ALL=C`

2. Create a network topology => enable openFlow with Controller's ip => install openVSwitch on each node to build the bridges with controller

- [x] Tested by me



#### Lab11 SDN 

This one teaches us how to create SDN project

* SDN controller using floodlight
* Topology

- [x] Tested by me

##### This one is the most important one!!!





#### Notes

A interesting [article](https://www.fiber-optic-transceiver-module.com/openvswitch-vs-openflow-what-are-they-whats-their-relationship.html) about Openswitch and Openflow 

