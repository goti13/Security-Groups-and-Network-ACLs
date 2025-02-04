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

Now that we've removed the outbound rule, let's take a look at how it appears in the configuration.


![image](https://github.com/user-attachments/assets/5d9ff714-fa85-430b-8abd-198ed24ebd40)

After making this change, let's test whether we can still access the website.

![image](https://github.com/user-attachments/assets/bd5fb72c-a9ae-47b7-afd1-0b260bf42dda)
![image](https://github.com/user-attachments/assets/5bfb706d-0227-4264-83ef-bbf79a6acd39)

So, even though we've removed the outbound rule that allows all traffic from the instance to the outside world, we can still access the website. According to the logic we discussed, when a user accesses the instance, the inbound rule permits HTTP protocol traffic to enter. However, when the instance sends data to the user's browser to display the website, the outbound rule should prevent it. Yet, we're still able to view the website. Why might that be?

Security groups are stateful, which means they automatically allow return traffic initiated by the instances to which they are attached. So, even though we removed the outbound rule, the security group allows the return traffic necessary for displaying the website, hence we can still access it.

let's explore the scenario,
If we delete both the inbound and outbound rules, essentially, we're closing all access to and from the instance. This means no traffic can come into the instance, and the instance cannot send any traffic out. So, if we attempt to access the website from a browser or any other client, it will fail because there are no rules permitting traffic to reach the instance. Similarly, the instance won't be able to communicate with any external services or websites because all outbound traffic is also blocked.

7. You will be able to delete the inbound rule in the same way we have deleted the outbound rule.'
   
a) Go to outbound tab.

b) Click on edit inbound rule

![image](https://github.com/user-attachments/assets/8311b0e7-f508-4dac-97df-bd89dd524b6c)

C) Click on delete,

d) Click on "Save rule."

![image](https://github.com/user-attachments/assets/18f5ff9c-0e98-4806-802b-d56bf235a854)

Currently, let's have a look at how our inbound and outbound rules are configured.

![image](https://github.com/user-attachments/assets/73ed1f80-6e7e-479f-ba74-5dbf2dad24d2)

![image](https://github.com/user-attachments/assets/32599458-65c7-4efa-aeee-bc60ff9a24e9)

Now, as both the inbound and outbound rules deleted, there's no way for traffic to enter or leave the instance. This means that any attempt to access the website from a browser or any other client will fail because there are no rules permitting traffic to reach the instance. 

In this state, the instance is essentially isolated from both incoming and outgoing traffic.
So you can't access the website now.

![image](https://github.com/user-attachments/assets/35647f11-1e91-4713-a530-0a9b82a7f78a)
![image](https://github.com/user-attachments/assets/0135b588-6be8-4e1e-a8a2-bba9fa3626cd)

In the next scenario,
We'll add a rule specifically allowing HTTP traffic in the outbound rules. This change will enable the instance to initiate outgoing connections over HTTP.

8. Click on edit outbound rule in the outbound tab,

![image](https://github.com/user-attachments/assets/14058a69-1321-4fa1-83f5-46a4e2ca33bd)

a) Click on "add rule"

b) Choose type.

c) Choose destination.

d) Choose CIDR.

e) Click on "save rules"


![image](https://github.com/user-attachments/assets/4b47cd95-ed81-4421-8e1f-0ff9229a8540)

![image](https://github.com/user-attachments/assets/8d735c33-4964-4341-a14f-b69088910fac)


![image](https://github.com/user-attachments/assets/c0f6c263-caaf-4043-835d-1722873e937f)

Now, let's see if we can access the website,

![image](https://github.com/user-attachments/assets/3ac5e9c8-eba8-4c46-9ce9-2edb28ea5d2e)
![image](https://github.com/user-attachments/assets/c6b6c3c3-138b-486f-bd2e-5054ea38c22d)

So, we are not able to see it.

But if you look here, we are able to go to the outside world from the instance. We are using here.

![image](https://github.com/user-attachments/assets/f630dd67-301d-44ef-9586-b7606c74c354)

Note- curl is a command-line tool that fetches data from a URL.
As a result, the instance will be able to fetch data from external sources or communicate with other HTTP-based services on the internet. This adjustment ensures that while incoming connections to the instance may still be restricted, the instance itself can actively communicate over HTTP to external services.

Part - 2

Let's come to NACL

1. First navigate to the search bar and search for VPC.
a) Then click on VPC.|

![image](https://github.com/user-attachments/assets/96695427-8739-4407-a1a7-5d460631da8b)

2. Navigate to the Network ACLs in the left sidebar.
   
a) Click on "Create Network ACL."

![image](https://github.com/user-attachments/assets/7590b0d6-5c4d-42c5-ba6f-a3be1a2b65a9)

3. Now, provide a name for your Network ACL,
   
a) Choose the VPC you created in the [Previous session)(./AWS VPC mini project.md) for the practical on VPC creation,
b) Then click on "Create network ACL".

![image](https://github.com/user-attachments/assets/c65ccdf3-ca5a-44ff-9cb7-0af1912c4900)

4. If you selected the Network ACL you created,
   
a) navigate to the "Inbound" tab.
By default, you'll notice that it's denying all traffic from all ports.

![image](https://github.com/user-attachments/assets/c4dd0c47-fd1d-40a5-aaa5-efb11d888243)

Similarly, if you look at the outbound rules, you'll observe that it's denying all outbound traffic on all ports by default.

b) Select the NACL.
c) And navigate to the "Outbound" tab.

![image](https://github.com/user-attachments/assets/d920e4c9-d59d-4259-8bf3-21cf3bb2291a)

5. To make changes,
   
a) select the NACL,
b) Go to the "Inbound" tab.
c) And click on "Edit inbound rules".

![image](https://github.com/user-attachments/assets/ef098bc3-a1a1-45a1-b191-150354d714c5)

6. Now, click on "Add new rule."

![image](https://github.com/user-attachments/assets/084a841e-f3ef-4713-827d-7e380f0d8997)

7. Now, choose the rule number.
   
a) Specify the type.

b) Select the source.

c) And determine whether to allow or deny the traffic.

d) Then click on "Save changes."

![image](https://github.com/user-attachments/assets/8d1ab36d-f702-468f-94c4-5866aa4952e2)


Currently, this NACL is not associated with any of the subnets in the VPC.

![image](https://github.com/user-attachments/assets/82661aa8-8233-40e0-b03f-8d6d353d2e72)

8. Let's associate it.
   
a) Select your NACL.

b) Click on "Actions."

c) Choose "Edit subnet association."


![image](https://github.com/user-attachments/assets/851f7e34-e424-40e8-b87e-cff4cab61c36)

d) Then select your public subnet, as our instance resides in the public subnet.

![image](https://github.com/user-attachments/assets/a6a50a4b-1fee-4e57-b218-dc4888fa8dc6)

Once selected, you'll see it listed under "Selected subnets".

e) Finally, click on "Save changes".

![image](https://github.com/user-attachments/assets/4cd8572f-54c2-4e3b-83c4-f66440aa62c7)

You have successfully associated your public subnet to this NACL.

![image](https://github.com/user-attachments/assets/0197aba8-a10a-4e24-a7cc-00a1702fb703)

As soon as you have attached this NACL to your public subnet, and then you try to access the website again by typing the URL http://54.255.228.191/, you will notice that you are unable to see the website.


![image](https://github.com/user-attachments/assets/ef5d6da0-068d-4099-a58d-5d54a25d20a8)

Although we've permitted all traffic in the inbound rule of our NACL, we're still unable to access the website. This raises the question: why isn't the website visible despite these permissions?
The reason why we're unable to access the website despite permitting inbound traffic in the NACL is because NACLs are stateless. They don't automatically allow return traffic. As a result, we must explicitly configure rules for both inbound and outbound traffic.
Even though the inbound rule allows all traffic into the subnet, the outbound rules are still denying all traffic.
You can see,

![image](https://github.com/user-attachments/assets/07c5fcce-843a-4626-b697-74e1f1340ac9)

![image](https://github.com/user-attachments/assets/d3cd6d15-c419-47f4-b984-8843b21725fb)

![image](https://github.com/user-attachments/assets/e8f26d14-a74f-4af0-ba57-8523880a281e)

Not able to see website because you are able to go inside of the subnet because of the inbound rule (allow all) but any traffic from subnet is not allowed to go outside due to the
outbound rule (deny all).

9. If we allow outbound traffic as well,
    
a) Choose you NACL.
b) Go to outbound tab.
c) Click on "Edit outbound rules."

![image](https://github.com/user-attachments/assets/17663092-04dd-41f2-8007-f358e9c9ce31)

d) Click on "Add rule."

![image](https://github.com/user-attachments/assets/7ce3f10f-3eb4-413e-946e-e1412805e361)

e) Duplicate the process you followed for creating the inbound rules to establish the outbound rules in a similar manner.

![image](https://github.com/user-attachments/assets/a5d7a13f-d4e8-46ee-8437-b049fee3afc3)


You have successfully created the rules,


![image](https://github.com/user-attachments/assets/9dbb7a7d-5472-4fed-ac5d-cc5abc210f25)

Upon revisiting the website, you should now be able to access it without any issues.

![image](https://github.com/user-attachments/assets/0c267b8d-edd6-4305-9dc9-40894511e20c)
![image](https://github.com/user-attachments/assets/ffa11163-da61-4a86-bbd0-f1a07018347c)

Now, let's see one more interesting scenario,

In this scenario:
Security Group: Allows inbound traffic for HTTP and SSH protocols and permits all outbound traffic.
Network ACL: Denies all inbound traffic. Let's observe the outcome of this configuration.
Security group,
Configuring it,

![image](https://github.com/user-attachments/assets/baf1e0dd-6d4a-4159-b840-d52963060f3f)

![image](https://github.com/user-attachments/assets/f49dfbc7-9169-47c1-80de-b3ad52d9dcab)

![image](https://github.com/user-attachments/assets/f0cf51d4-958b-47f9-b833-c1af7d9492e1)

![image](https://github.com/user-attachments/assets/e29eee5d-0233-4899-907e-3f1165cc837a)

NACL,

Let's remove it so by default it be denied all traffic.

![image](https://github.com/user-attachments/assets/a7f07e8f-d311-4246-944e-01f0e10063f8)

![image](https://github.com/user-attachments/assets/7994f359-80ca-4d60-bb2d-92f764e88b61)

Additionally, the outbound rule will be removed, defaulting to deny all traffic by default.

![image](https://github.com/user-attachments/assets/c1ddba70-b9b7-4d3e-ab82-124de9b9c868)

![image](https://github.com/user-attachments/assets/c9888e60-be95-4dad-ac6a-6bc8d6374124)

Now, let's try to access the website,

![image](https://github.com/user-attachments/assets/e4b847ab-4760-4d08-85eb-634c1818a024)
![image](https://github.com/user-attachments/assets/257ce490-7568-4341-85c2-9f199b6dfdbc)

So we are unable to access the website. why? Even if we have allowed inbound traffc for HTTP in security group.

Imagine you're at the entrance of a building, and there's a security guard checking everyone who wants to come in. That security guard is like the NACL. They have a list of rules (like "no backpacks
allowea or no tood or arinks inside , and they check each person against these rules as they enter.

Once vou're inside the building there's another laver of security at each room's door These are like the Security Groups. Each room has its own rules like "onlv emplovees allowed" or "no nets " Once you're inside the building, there's another layer of security at each room's door. These are like the Security Groups. Each room has its own rules, like "only employees allowed" or "no pets.
These rules are specific to each room, just like Security Groups are specific to each EC2 instance.

So, the traffic first goes through the NACL (the security guard at the entrance), and if it passes those rules, it then goes through the Security Group (the security check at each room's door). If it doesn't meet any of the rules along the way, it's denied entry.

The reason we can't see the website is because the NACL has denied inbound traffic. This prevents traffic from reaching the security group, much like a security guard not allowing entry to another room if access to the building is denied. Similarly, if someone can't enter a building, they can't access any rooms inside without first gaining entry to the building." room if access to the building is denied. Similarly, if someone can't enter a building, they can't access any rooms inside without first gaining entry to the building."

Let's have a look on some scenarios and their outcomes,

• NACL allows all inbound and outbound traffic, Security Group denies all inbound and outbound traffic: Outcome: Website access will be blocked because the Security Group denies all traffic,
overriding the NACL's allowance.

• NACL denies all inbound and outbound traffic, Security Group allows all inbound and outbound traffic: Outcome: Website access will be blocked because the NACL denies all traffic, regardless of the Security Group's allowances.

• NACL allows HTTP inbound traffic, outbound traffic is denied, Security Group allows inbound traffic and denies outbound traffic: Outcome: Website access will be allowed because the Security Group allows HTTP inbound traffic, regardless of the NACL's allowances. However, if the website requires outbound traffic to function properly, it won't work due to the Security Group's denial of outbound traffic.

• NACL allows all inbound and outbound traffic, Security Group allows HTTP inbound traffic and denies outbound traffic: Outcome: Website access will be allowed because the Security Group allows HTTP inbound traffic, regardless of the NACL's allowances. However, if the website requires outbound traffic to function properly, it won't work due to the Security Group's denial of outbound traffic.
traffic.
• NACL allows all inbound and outbound traffic, Security Group allows all inbound and outbound traffic: Outcome: Website access will be allowed, as both NACL and Security Group allow all

• NACL denies all inbound and outbound traffic, Security Group allows HTTP inbound traffic and denies outbound traffic: Outcome: Website access will be blocked because the NACL denies all
traffic, regardless of the Security Group's allowances.


Project Reflection:

• Successfully configured Security Groups and NACLs to control inbound and outbound traffic in AWS.

• Identified the differences between Security Groups and NACLs and their respective roles in network security.

• Explored various scenarios to understand how Security Groups and NACLs interact and impact network traffic.

• Learned valuable troubleshooting techniques for diagnosing and resolving network connectivity issues in AWS.

• Overall, gained practical experience and confidence in managing network security within AWS environments.





























