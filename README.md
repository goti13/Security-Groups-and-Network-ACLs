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
