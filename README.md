# Security-Groups-and-Network-ACLs

Security Groups and NACLs mini project

During this project, we'll explore the core concepts of Amazon Web Services (AWS), specifically focusing on Security Groups and Network Access Control Lists (ACLs). Our objective is to understand these fundamental components of AS infrastructure, including how Security Groups control inbound and outbound traffic to EC2 instances, and how NACLs act as subnet-level firewalls, regulating traffic entering and exiting subnets. Through practical demonstrations and interactive exercises, well navigate the AWS management console to deploy and manage these critical components effectively.

Project Goals:
• Understand the concepts of Security Groups and Network Access Control Lists (NACLs) in AWS.
• Explore how Security Groups and NACLs function as virtual firewalls to control inbound and outbound traffic.
• Gain hands-on experience with configuring Security Groups and NACLs to allow or deny specific types of traffic.

Learning Outcome:
• Gain proficiency in configuring Security Groups and NACLs to control network traffic within AWS environments.
• Understand the differences between Security Groups and NACLs, including their scope, statefulness, and rule configurations.
• Learn how to troubleshoot network connectivity issues by analyzing Security Group and NACL configurations.
• Develop a deeper understanding of AWS networking concepts and best practices for securing cloud environments.

Security Group (SG):
Inbound Rules: Rules that control the incoming traffic to an AWS resource, such as an EC2 instance or an RDS database.
Outbound Rules: Rules that control the outgoing traffic from an AWS resource.
Stateful: Security groups automatically allow return traffic initiated by the instances to which they are attached.
Port: A communication endpoint that processes incoming and outgoing network traffic. Security groups use ports to specify the types of traffic allowed.
Protocol: The set of rules that governs the communication between different endpoints in a network. Common protocols include TCP, UDP, and ICMP.

Network Access Control List (NACL):
Subnet-level Firewall: NACLs act as a firewall at the subnet level, controlling traffic entering and exiting the subnet.
Stateless: Unlike security groups, NACLs are stateless, meaning they do not automatically allow return traffic. You must explicitly configure rules for both inbound and outbound traffic.
Allow/Deny: NACL rules can either allow or deny traffic based on the specified criteria.
Ingress: Refers to inbound traffic, i.e., traffic entering the subnet.
Egress: Refers to outbound traffic, i.e., traffic exiting the subnet.
CIDR Block: Specifies a range of IP addresses in CIDR notation (e.g., 10.0.0.0/24) that the NACL rule applies to.


Default Settings:
Default Security Group: Every VPC comes with a default security group that allows all outbound traffic and denies all inbound traffic by default.
Default NACL: Every subnet within a VPC is associated with a default NACL that allows all inbound and outbound traffic by default.

What is Security Group?

Imagine you're hosting a big party at your house. You want to make sure only the people you invite can come in, and you also want to control what they can do once they're inside.
AWS security groups are like bouncers at the door of your party. They decide who gets to come in (inbound traffic) and who gets kicked out (outbound traffic).
Each security group is like a set of rules that tells the bouncers what's allowed and what's not.
For example, you can create a security group for your web server that only allows traffic on port 80 (the standard port for web traffic) from the internet. This means only web traffic can get through, keeping your server safe from other kinds of attacks.
Similarly, you can have another security group for your database server that only allows traffic from your web server. This way, your database is protected, and only your web server can access it, like a VIP area at your party.
In simple terms, security groups act as barriers that control who can access your AWS resources and what they can do once they're in. They're like digital bouncers that keep your party (or your cloud) safe and secure.


What is NACL?
NACL stands for Network Access Control List. Think of it like a security checkpoint for your entire neighborhood in the AWS cloud. Imagine your AWS resources are houses in a neighborhood, and you want to control who can come in and out. That's where NACLs come in handy.
NACLs are like neighborhood security guards. They sit at the entrance and check every person (or packet of data) that wants to enter or leave the neighborhood.

But here's the thing: NACLs work at the subnet level, not the individual resource level like security groups. So instead of controlling access for each house (or AWS resource), they control access for the entire neighborhood (or subnet).
You can set rules in your NACL to allow or deny traffic based on things like IP addresses, protocols, and ports. For example, you can allow web traffic (HTTP) but block traffic on other ports like FTP or SSH.

Unlike security groups, which are stateful (meaning they remember previous interactions), NACLs are stateless. This means you have to explicitly allow inbound and outbound traffic separately, unlike security groups where allowing inbound traffic automatically allows outbound traffic related to that session.

In simple terms, NACLs act as gatekeepers for your AWS subnets, controlling who can come in and out based on a set of rules you define. They're like the security guards that keep your neighborhood (or your AWS network) safe and secure.

Difference between Security Groups and NACL


Security Groups in AWS act like virtual firewalls that control traffic at the instance level. They define rules for inbound and outbound traffic based on protocols, ports, and IP addresses. Essentially, they protect individual instances by filtering traffic, allowing only authorized communication.
On the other hand, Network Access Control Lists (NACLs) function at the subnet level, overseeing traffic entering and leaving subnets. They operate as a barrier for entire subnets, filtering traffic based on IP addresses and protocol numbers. Unlike security groups, NACLs are stateless, meaning they don't remember the state of the connection, and each rule applies to both inbound and outbound traffic independently.



