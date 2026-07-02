import random
import os

# Read and remove duplicates
with open("cleaned.txt", "r") as f:
    data = list(set(line.strip() for line in f if line.strip()))

random.shuffle(data)

sizes = [100, 200, 300, 400]
overlaps = [0, 25, 50, 75]

os.makedirs("datasets", exist_ok=True)

for size in sizes:
    for overlap in overlaps:

        shared = int(size * overlap / 100)

        unique = size - shared

        required = shared + unique + unique

        if required > len(data):
            raise ValueError(
                f"Not enough IOCs for size={size}, overlap={overlap}%"
            )

        random.shuffle(data)

        shared_items = data[:shared]
        alice_unique = data[shared:shared + unique]
        bob_unique = data[shared + unique:required]

        alice = shared_items + alice_unique
        bob = shared_items + bob_unique

        random.shuffle(alice)
        random.shuffle(bob)

        with open(f"datasets/alice_{size}_{overlap}.txt", "w") as f:
            f.write("\n".join(alice))

        with open(f"datasets/bob_{size}_{overlap}.txt", "w") as f:
            f.write("\n".join(bob))

print("Finished generating datasets.")
