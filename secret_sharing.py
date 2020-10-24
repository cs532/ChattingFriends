import numpy as np
from tinyec import registry, ec
import secrets
from scipy.interpolate import lagrange


curve = registry.get_curve('secp256r1')


def gen_private_key():
    return secrets.randbelow(curve.field.n)


def gen_public_key(private):
    return private * curve.g


def establish_secret(friend_pub_key, private_key):
    point_setup = friend_pub_key.split()
    x = point_setup[0][1:-1]
    y = point_setup[1][0:-1]
    pub = ec.Point(curve, int(x), int(y))
    shared_secret = (private_key * pub)

    return shared_secret.x


def quick_parser(num):

    hexi = hex(num)
    num_list = []
    i = 2
    while i < 34:
        num_list.append(int((hexi[i:i+2]), 16))
        i += 2

    return np.asarray(num_list).reshape((4, 4))


def proper_parser(num):

    binary = bin(num)
    num_list = []
    i = 2
    while i < 130:
        num_list.append(int((binary[i:i+8]), 2))
        i += 8

    return np.asarray(num_list).reshape((4, 4))


# this is a mersenne prime number and this controls how secure the key is
# must be less than 2**32 due to the use of np.rand()
prime = 2**31 - 1


# create_polynomial returns the value of a polynomial given an x and the randomly generated coefficients
def create_polynomial(x, coefficients):
    fx = 0
    for i in range(len(coefficients)):
        fx += x**i * int(coefficients[i])
    return fx % prime


# generate_shard returns an array of shards to be distributed to the users
def generate_shard(numCreators, numToOpen, key):
    c = []
    c.append(int(key))
    for x in range(int(numToOpen)-1):
        c.append(np.random.randint(prime-1))
    shards = []
    for x in range(int(numCreators)):
        shards.append([x+1, create_polynomial(x+1, c)])
    return shards


# compile_shards takes in an array of shards then returns the resulting key
def compile_shards(shards):
    x = np.array([])
    y = np.array([])
    for i in range(len(shards)):
        x = np.append(x, shards[i][0])
        y = np.append(y, shards[i][1])
    poly = lagrange(x, y)
    return np.polynomial.polynomial.Polynomial(poly).coef[-1] % prime


if __name__ == "__main__":
# test driver code below \/ \/ \/

    numCreators = input("please enter the number of people: ")
    numToOpen = input("please enter the number of people needed to open the key: ")
    key = input("please enter the key: less than 2147483647: ")
    numpeople = input("please enter the number of people attempting to generate the key: ")
    shards = generate_shard(numCreators, numToOpen, key)
    print("the generated shards are: ")
    del shards[int(numpeople):int(numCreators)]
    print(shards)
    print("the key gotten using the shards is: ")
    print(compile_shards(shards))
