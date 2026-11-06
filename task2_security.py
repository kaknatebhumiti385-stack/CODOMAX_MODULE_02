
import json
import fnmatch

# Load security policy
with open("security_policy.json", "r") as file:
    policy = json.load(file)


def check_permission(action, resource):

    explicit_deny = False
    allowed = False

    for statement in policy["Statement"]:

        effect = statement["Effect"]
        actions = statement["Action"]
        resources = statement["Resource"]

        action_match = any(
            fnmatch.fnmatchcase(action, pattern)
            for pattern in actions
        )

        resource_match = any(
            fnmatch.fnmatchcase(resource, pattern)
            for pattern in resources
        )

        if action_match and resource_match:

            if effect == "Deny":
                explicit_deny = True

            elif effect == "Allow":
                allowed = True

    if explicit_deny:
        return "DENIED (Explicit Deny)"

    if allowed:
        return "ALLOWED"

    return "DENIED (No Permission)"


# Permission testing
tests = [
    ("Read S3 Object",
     "s3:GetObject",
     "arn:aws:s3:::codomax-demo-bucket/file.txt"),

    ("List S3 Bucket",
     "s3:ListBucket",
     "arn:aws:s3:::codomax-demo-bucket"),

    ("Delete S3 Object",
     "s3:DeleteObject",
     "arn:aws:s3:::codomax-demo-bucket/file.txt"),

    ("Upload S3 Object",
     "s3:PutObject",
     "arn:aws:s3:::codomax-demo-bucket/file.txt")
]

print("\n===== CODOMAX TASK 2 =====")
print("AWS SECURITY & IAM POLICY TESTING\n")

for name, action, resource in tests:
    result = check_permission(action, resource)
    print(f"{name}: {result}")

print("\nSecurity testing completed!")
