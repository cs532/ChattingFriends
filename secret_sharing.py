import numpy as np
from scipy.interpolate import lagrange

np.random.seed(seed = 2)

p = 7919 #prime
g = 443  #base

def gen_private_key():
    return np.random.randint(low = 0,high = p-1)

def gen_public_key(private):
    return (g**private)%p

def establish_secret(friend_pub_key,private_key):
    return(friend_pub_key**private_key)%p

#this is a mersenne prime number and this controls how secure the key is
#must be less than 2**32 due to the use of np.rand()
prime = 2**31 - 1

#create_polynomial returns the value of a polynomial given an x and the randomly generated coefficients
def create_polynomial(x, coefficients):
    fx = 0
    for i in range(len(coefficients)):
        fx += x**i * int(coefficients[i])
    return fx % prime

#generate_shard returns an array of shards to be distributed to the users
def generate_shard(numCreators, numToOpen, key):
    c = []
    c.append(int(key))
    for x in range(int(numToOpen)-1):
        c.append(np.random.randint(prime-1))
    shards = []
    for x in range(int(numCreators)):
        shards.append([x+1, create_polynomial(x+1, c)])
    return shards

#compile_shards takes in an array of shards then returns the resulting key
def compile_shards(shards):
    x = np.array([])
    y = np.array([])
    for i in range(len(shards)):
        x = np.append(x, shards[i][0])
        y = np.append(y, shards[i][1])
    poly = lagrange(x, y)
    return np.polynomial.polynomial.Polynomial(poly).coef[-1] % prime
