import numpy as np

np.random.seed(seed = 2)

p = 7919 #prime
g = 443  #base

def gen_private_key():
    return np.random.randint(low = 0,high = p-1)

def gen_public_key(private):
    return (g**private)%p

def establish_secret(friend_pub_key,private_key):
    return(friend_pub_key**private_key)%p
