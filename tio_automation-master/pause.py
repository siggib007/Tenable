#!/usr/bin/env python3
#Disclaimer: This is NOT supported By Tenable!

# This script resumes all Paused Nessus Scans
import requests

#avoid insecure warning
requests.packages.urllib3.disable_warnings()

def grab_headers():
    #Enter Your Access keys
    access_key = '05cc2a10e8041f5cee62413f0e2e751607f5bc881d08cf6a51e7a73845190639'
    secret_key = 'ceb7bf537a6acfff79b15af69ad101f5aa7fbb75e20d21d4ef4c99ae91e3d0d1'

    #Set the Authentication Header
    headers = {'Content-type':'application/json','X-ApiKeys':'accessKey='+access_key+';secretKey='+secret_key}
    return headers


def get_data(url_mod):
    #Base URL
    url = "https://cloud.tenable.com"
    #Retreive Headers
    headers = grab_headers()
    #API Call
    r = requests.request('GET', url + url_mod, headers=headers, verify=False)
    #convert response to json
    data = r.json()
    #return data in json format
    return data

def post_data(url_mod):
    #Base URL
    url = "https://cloud.tenable.com"
    #Retreive Headers
    headers = grab_headers()
    #Post API data
    response = requests.post(url + url_mod, headers=headers, verify=False)
    #return raw response
    return response


def main():
    #grab all of the scans in t.io
    data = get_data('/scans')

    #loop through each scan
    for scans in data['scans']:

        print("Scan ID {} named {} is of type {} and has a status of {}".format(scans['id'],scans['name'],scans['type'],scans['status']))
        #idenify those that are running to be paused
        if scans['status'] == "running":

            #reduce alerts by looking for remote scans
            if scans['type'] != "":

                #try block to ignore errors
                try:
                    #need the ID for alerting the user
                    id = scans['id']
                    print ("pausing")

                    #request the scan be paused
                    post = post_data('/scans/' + str(id) + '/pause')

                    #decide what to do based on HTTP Codes
                    if post.status_code == 200:
                        print(" Your Scan " + str(id) + " Paused")
                    elif post.status_code == 409:
                        print("Wait a few seconds and try again")
                    elif post.status_code == 404:
                        print("yeah, this scan doesn't exist")
                    else:
                        print("It's possible this is already running")

                #ignore the error
                except Exception as err:
                    print ("unknown error {}".format(err))


if __name__ == '__main__':
    main()
