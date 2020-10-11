import numpy as np

# global
val_num_char = 127


def format_text(tex):

    print(tex)
    return tex


def list_to_int(text):
    # This function takes text and turns them into numbers between 0 and 25 inclusive
    numbers = []
    for i in range(len(text)):
        numbers.append(ord(text[i]))
    if len(text) % 2 == 1:
        numbers.append(23)
    return numbers


def pair_packing(lst):
    # Since we are working with a 2x2 matrix, we must pair the numerical value
    # of the letters must be paired in order for the multiplication to work
    i = 0
    repack = []
    while i < len(lst):
        repack.append([lst[i], lst[i+1]])
        i+=2        
    return repack


def de_pair(lst):
    # separates the paired list into a sequential list
    long_list = []
    i = 0
    while i < lst.shape[1]:
        long_list.append(lst[0][i])
        long_list.append(lst[1][i])
        i += 1
    return long_list


def int_to_ASCII(text):
    # grabes the ASCII value of the text, alters it to fit between 0 and 25 inclusively
    letters = []
    for i in range(len(text)):
        letters.append(chr(text[i]))
    return letters

# useful for debugging matrix mult.    
#def crazyprint(ls1,ls2):   
#    for i in range(len(ls1)):
#        print(" ")
#        print(ls1[i]," => " ,ls2[i])
#    print(" ")


def format_then_pair(text):
    # takes string, turns into pairs
    all_cap_s = format_text(text)
    list_of_chars = list(all_cap_s)
    list_ints = list_to_int(list_of_chars)
    pears = pair_packing(list_ints)
    return pears


def code_alg_hill(ciph, np_arr, leg):
    # the algorithm that encodes using a Hill cipher
    result = (ciph.dot(np_arr) % val_num_char).astype(int)
    return result
    

def calc_inverse():

    global hill, inv_hill
    # create the inverse matrix
    det_inv = det_inv_finder(hill[0,0]*hill[1,1]-hill[0,1]*hill[1,0])
    inv_mat = np.array([[hill[1,1], -(hill[0,1])],[-(hill[1,0]),hill[0,0]]])
    print(det_inv)
    print(inv_mat)
    inv_hill = (det_inv*inv_mat) % val_num_char
    return inv_hill


def det_inv_finder(det):
    # just iterate through all possible values that the mult. mod. inv. could be
    print(det)
    for i in range(val_num_char):
        if (det*i) % val_num_char == 1:
            return i
    print("ERROR")
    return "NO"


def back_to_str(num_pairs):
    # formatting the pairs back into a single sequential list
    coded_lst = int_to_ASCII(de_pair(num_pairs))
    coded_msg = ''.join(map(str, coded_lst))
    return coded_msg
    

def mass_encrypt(text, secret):
    pa = format_then_pair(text)
    ciph = [[3,5],[2,7]]
    hillm = np.asarray(ciph)
    result = code_alg_hill(hillm, np.array(pa).T, len(pa))
    coded_st = back_to_str(result)
    return coded_st


def mass_decrypt(text, secret):
    paired = format_then_pair(text)
    ciph = [[93, 115], [46,  58]]
    inv_hillm = np.asarray(ciph)
    result = code_alg_hill(inv_hillm, np.array(paired).T, len(paired))
    coded_st = back_to_str(result)
    return coded_st



if __name__ == "__main__":

    #basically a test script

    print("")
    print("Message:")
    # s is the plain text string you want to encrypt 
    s = "#HELP"
    pair1 = format_then_pair(s)
    # Cipher is the list form of the cypher you want to use
    cipher = [[3, 5], [2, 7]]
    hill = np.asarray(cipher)
    print("Hill Cipher:")
    print(hill)
    print("")
    
    inv_hill = calc_inverse()
    print("Inverse Hill:")
    print(inv_hill)
    print(" ")
    
    results = code_alg_hill(hill,np.array(pair1).T,len(pair1))
    coded_str = back_to_str(results)
    print("Coded Message:")
    new_pairs = format_then_pair(coded_str)
    uncoded = code_alg_hill(inv_hill,np.asarray(new_pairs).T,len(new_pairs))
    uncoded_str = back_to_str(uncoded)
    print("")
    print("Uncoded Message:")
    print(uncoded_str)
    print("")
    print("Check mass_encrypt")
    check1 = mass_encrypt(s, 0)
    print(check1)
    print("Check mass_decrypt")
    check2 = mass_decrypt(check1, 0)
    print(check2)

