import string
import datetime

# precondition: alphanumerics with '.', '-', and ',' allowed
def isValidName(name):
    if type(name)!=str:
        print("name not valid")
        return False
    for letter in name:
        if letter.isdigit() or letter in """!"#$%&()*+/:;<=>?@[\]^_`{|}~""":
            print("name not valid")
            return False
    return True

# precondition: 9 character string, alphas in caps
def isValidId(nric):
    # check string of length 9
    if type(nric) != str:
        print("ic not valid")
        return False
    if (len(nric)!=9 or not nric[1:8].isdigit()):
        print("ic not valid")
        return False

    # check prefix
    if nric[0] not in "STFG":
        print("ic not valid")
        return False

    # verify checksum
    weight = [2,7,6,5,4,3,2]
    st_alphas = "ABCDEFGHIZJ"
    fg_alphas = "KLMNPQRTUWX"
    product_sum = 0
    offset = 4 if (nric[0] == "T" or nric[0] == "G") else 0
    for i in range(1,8):
        product_sum += int(nric[i])*(weight[i-1])
    suffix_index = (11-offset-product_sum%11)-1
    if (nric[0] == "S" or nric[0] == "T"):
        if (nric[8]==st_alphas[suffix_index]):
            return True
        print("ic not valid")
        return False
    elif (nric[0] == "F" or nric[0] == "G"):
        if (nric[8]==fg_alphas[suffix_index]):
            return True
        print("ic not valid")
        return False
    print("ic not valid")
    return False

# precondition: DD/MM/YYYY
def isValidDob(dob):
    if (type(dob) != str):
        print("birthday not valid")
        return False
    leap_year = False
    split = dob.split("/")
    if len(split) != 3:
        print("birthday not valid")
        return False
    for num in split:
        if not num.isdigit():
            print("birthday not valid")
            return False
    if len(split[0]) != 2 or len(split[1]) != 2 or len(split[2])!= 4:
        return False
    if int(split[1]) > 12 or int(split[1]) == 0:
        return False
    # check if input date exceeds current date
    try:
        if (datetime.datetime(int(split[2]),int(split[1]),int(split[0])) > datetime.datetime.now()):
            print("birthday not valid")
            return False
    except:
        print("birthday not valid")
        return False
    if (int(split[2]) % 4 == 0 and (int(split[2]) % 100 != 0 or int(split[2]) % 400 == 0)):
        leap_year = True
    print(leap_year)
        
    long_months = ['01', '03', '05', '07', '08', '10', '12']
    short_months = ['04', '06', '09', '11']

    # if Feb > 28 on normal year, return false
    if split[1] == '02' and not leap_year and int(split[0]) > 28:
        print("birthday not valid")
        return False
    # if Feb > 29 on leap year, return false
    elif split[1] == '02' and leap_year and int(split[0]) > 29:
        print("birthday not valid")
        return False
    elif split[1] in long_months and int(split[0]) > 31:
        print("birthday not valid")
        return False
    elif split[1] in short_months and int(split[0]) > 31:
        print("birthday not valid")
        return False
    return True

# precondition: 6 digits
def isValidPostCode(postcode):
    # Postcode 74XXXX or 83XXXX-99XXXX does not exist
    if (postcode[0:2] == "74" or int(postcode[0:2]) > 82):
        print("Postcode not valid")
        return False
    if len(postcode) != 6:
        print("Postcode not valid")
        return False
    if not postcode.isdigit():
        print("Postcode not valid")
        return False
    return True

#Takes in a dictionary and checks if all the values are valid
def isValidInput(inp):
    if not (isValidName(inp["name"])) or not (isValidId(inp["id_number"])) or not (isValidDob(inp["dob"])) or not (isValidPostCode(inp["postal_code"])):
        return False

    else:
        return True

