def isValidName(name):
    if type(name)!=str:
        return False
    for letter in name:
        if letter.isdigit() or letter in string.punctuation:
            return False
    return True

def isValidId(idee):
    if type(idee) != str:
        return False
    for letter in idee:
        if not letter.isalnum():
            return False
    return True

def isValidDob(dob):
    split = dob.split("/")
    if len(split) != 3:
        return False
    for num in split:
        if not num.isdigit():
            return False
    if len(split[0]) != 2 or len(split[1]) != 2 or len(split[2])!= 4:
        return False

    if int(split[1]) > 12 or int(split[1]) == 0:
        return False

    long_months = ['01', '03', '05', '07', '08', '10', '12']
    short_months = ['04', '06', '09', '11']


    if split[1] == '02' and int(split[0]) > 29:
        return False
    elif split[1] in long_months and int(split[0]) > 31:
        return False
    elif split[1] in short_months and int(split[0]) > 31:
        return False

    return True

def isValidPostCode(postcode):
    if len(postcode) != 6:
        return False
    if not postcode.isdigit():
        return False
    return True

#Takes in a dictionary and checks if all the values are valid
def isValidInput(inp):
    if not (isValidName(inp["name"])) or not (isValidId(inp["id_number"])) or not (isValidDob(["dob"])) or not (isValidPostCode(["postal_code"])):
        return False

    else:
        return True