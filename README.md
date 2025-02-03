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

Note- In security groups, there's no explicit "deny" option as seen in NACLs; any rule configured within a security group implies permission, meaning that if a rule is established, it's automatically allowed.
Let's come to the practical part,
This practical will be in Two parts-

1. Security group
2. NACL
   
Security group
• Initially We'll examine the configuration of inbound and outbound rules for security groups.
• Create a security group allowing HTTP for all traffic and attach it to the instance.

Explore various scenarios:
• Implement inbound traffic rules for HTTP and SSH protocols and allow outbound traffic for all.
• Configure inbound rules for HTTP with no outbound rules.
• Remove both inbound and outbound rules.
• Have no inbound rules but configure outbound rules for all traffic.


NACL

• Examine the default settings for both inbound and outbound rules in NACL configuration.
• Modify the inbound rules to permit traffic from any IPv4 CIDR on all ports.
• Adjust the outbound rules to allow traffic to all CIDRs.
Part - 1
Just a quick reminder about the subnets we configured in our VPC in the [Previous project] In the public subnet, we've created an EC2 instance that is running, hosting our website. Now, let's take a moment to see if we can access the website using its public IP address.
So this EC2 instance hosts our website.


![image](https://github.com/user-attachments/assets/298a7cbb-3c56-480f-b4b0-3e248228b715)

Here's the security group configuration for the instance. In the inbound rules, only IPv4 SSH traffic on port 22 is permitted to access this instance.

![image](https://github.com/user-attachments/assets/f8ffdd50-423b-42cb-a917-5053872aa1db)

For the outbound rule, you'll notice that all IPv4 traffic with any protocol on any port number is allowed, meaning this instance has unrestricted access to anywhere on the internet.

![image](https://github.com/user-attachments/assets/11156f1e-03f6-4b45-8462-d8b47fbb2f78)


Now, let's test accessibility to the website using the public IP address assigned to this instance.
Here, let's retrieve the public IP address.


![image](https://github.com/user-attachments/assets/919de670-9488-429b-9457-6aefabd3b709)


If you enter "http:// 54.255.228.191" into your Chrome browser, and hit enter, you'll notice that the page doesn't load; it keeps attempting to connect. And finally it'll show this page. After some time, you'll likely see a page indicating that the site can't be reached.

![image](https://github.com/user-attachments/assets/b7a182bb-3600-469b-bffe-8b90dffcc45d)


![image](https://github.com/user-attachments/assets/1061f993-7eae-42c9-a13a-558a6d08bd27)


This is because of the security group, because we haven't defined HTTP protocol in the security group so whenever the outside world is trying to go inside our instance and trying to get the data, security group is restricting it and that's why we are unable to see the data
To resolve this issue, we can create a new security group that allows HTTP (port 80) traffic.
1. Navigate to the "Security Groups" section on the left sidebar.
a) Then click on "Create Security Group".

![image](https://github.com/user-attachments/assets/089f916d-daed-4895-a764-9c0ad9bb6d17)

2. Please provide a name and description for the new security group.
a) Ensure to select your VPC during the creation process.

![image](https://github.com/user-attachments/assets/67f25e03-7b9f-43b3-9f95-fb80b508d564)

b) Click on add rule.

![image](https://github.com/user-attachments/assets/57b40239-e634-44e5-b8ff-2dc48241fb18)

This security group has no inbound rules.

![image](https://github.com/user-attachments/assets/39bacac9-409c-4a4a-a4e0-03b64f77c2ba)

c) Now, select "HTTP" as the type.

![image](https://github.com/user-attachments/assets/2b1f619a-85a5-40cf-b4f4-270f91312bc0)

d) Use 0.0.0.0/0 as the CIDR Block. (Here we are allowing every CIDR block by using this CIDR).

![image](https://github.com/user-attachments/assets/6cc5c363-f3fd-4b3c-b3a2-4af8f3c32a49)

e) Keep outbound rules as it is.


![image](https://github.com/user-attachments/assets/ae4ed7b5-e0ac-422d-b253-dd833621fc3f)

f) Now, click on Create security group.

![image](https://github.com/user-attachments/assets/b2eb731b-c088-47dc-b08e-16033941e88a)


Now, it is being created successfully.

![image](https://github.com/user-attachments/assets/61e1bde2-c629-4966-9c20-fb04d2f956ea)

Let's attach this security group to our instance.

3. Now navigate to the instance section of left side bar.
   
a) Select the instance.
b) Click on "Actions."
c) Choose "security.

![image](https://github.com/user-attachments/assets/844baff3-ee1d-4c24-bfe2-a764a60b0f78)

d) Click on "Change security group."

![image](https://github.com/user-attachments/assets/e8e9aa22-0034-4f2f-8203-faf85bde67b0)


4. Choose the security group you created.

![image](https://github.com/user-attachments/assets/1b80b91f-52e1-4ed2-bd73-2aff83c5423b)

a) Click on "Add security group"

![image](https://github.com/user-attachments/assets/f0d82c68-afca-4734-a271-be7e9beb1ac9)

b) You can see security group is being added, Click on "save."

Note - The security group named "Launch Wizard" you see is the default security group automatically attached when creating the instance. You can also edit this security group if needed.

![image](https://github.com/user-attachments/assets/7fd3ec3a-2ca7-4120-bdd6-b1f9c0153d45)
![image](https://github.com/user-attachments/assets/7326d579-de60-4b91-b3ef-953eaa1fba4b)

5. Now it is being attached successfully,
   
a) If you again copy the public IP address,

![image](https://github.com/user-attachments/assets/307cf0a3-c3e9-480d-aae6-d980b4068dde)

b) And write http:// 54.255.228.191 in Chrome, We'll be able to see the data of our website.

![image](https://github.com/user-attachments/assets/6d3897fd-eef4-48e3-b46b-702e9b93d05c)
![image](https://github.com/user-attachments/assets/2d7c54e1-250c-4434-acc9-28eb5c852b87)

Currently, let's take a look at how our inbound and outbound rules are configured.
This setup allows the HTTP and SSH protocols to access the instance.

![image](https://github.com/user-attachments/assets/92c3a347-0311-4059-a2ff-79508a15e105)

The outbound rule permits all traffic to exit the instance.

![image](https://github.com/user-attachments/assets/1d6d12f8-abfb-454d-9192-da7c035fd004)

Through this rule, we're able to access the website.

![image](https://github.com/user-attachments/assets/562bd24c-e78f-43db-9dee-ddc97615b7ce)
![image](https://github.com/user-attachments/assets/a0fc4a6c-4f9b-48f7-ad19-0f4565fd8702)

6. let's see how removing the outbound rule affects the instance's connectivity. Means now, no one can go outside to this instance.
   
a) Go to outbound tab.

b) Click on "edit outbound rules".

![image](https://github.com/user-attachments/assets/bd96c53d-36de-4847-b38a-9ad803f3048d)

c) Click on "Delete."

d) Click on "Save rules."

![image](https://github.com/user-attachments/assets/92631e0b-cc14-4cf6-addf-e211c7b95f81)











