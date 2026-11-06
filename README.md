# network-error-logging-tools
Network Error Logging (NEL) tools is a set of Python tools to:
* Check a remote webserver's current NEL headers (live)
* Submit fake NEL reports to a NEL Reporting Endpoint
* Stand up a Reporting Endpoint in AWS using CloudFormation, API Gateway, Lambda and DynamoDB.

Steps to implment for yourself:
1. **Deploy** the NEL endpoint, with custom hostname, and customer TLS certificate (ACM) in AWS using the CloudFormation template.
1. **Test** your NEL endpoint with the tester script: reports should end up sitting in DynamoDB.
1. **Add** the NEL header to your web site(s) 
1. **Check** the NEL header on your web site(s) using the test script
1. **Adjust** the *success_fraction* and *failure_fraction* on your NEL header to reach the right balance of reports versus noise.
