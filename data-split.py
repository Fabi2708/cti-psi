import random

with open("cleaned.txt", "r") as f:
    data = list(set(line.strip() for line in f))

random.shuffle(data)

#split
shared = data[:80]
alice_only = data[80:320]
bob_only = data[320:640]

alice = shared + alice_only
bob = shared + bob_only

#save

with open("alice_dataset.txt", "w") as f:
    f.write("\n".join(alice))

with open("bob_dataset.txt", "w") as f:
    f.write("\n".join(bob))
