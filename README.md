# PIICrypt
> [`Microsoft/Presidio`](https://github.com/microsoft/presidio)-based PII (Personally Identifiable Information) detector and masker, built with Python3 and typr.

## Install
Set up the `uv` environment and install the Python3 application.
Additionally, install the [`en_core_web_lg`](https://spacy.io/models/en#en_core_web_lg) spaCy model for CPU-based, efficient English text processing.
And then, hit the command `piicrypt --help` to start.
```sh
uv sync
uv pip install pip
uv run spacy download en_core_web_lg
```

## Example usage
Suppose you have the following text file, named `input.txt`, which includes various PIIs, including an extra PII (GitHub Classic Token)
```
# pii_sample_conversation.txt

[Chat log between two developers]

Alice (alice.dev@example.com):  
Hey Bob, did you fix that deployment issue on the staging server?  

Bob (bob@example.org):  
Yeah, mostly. But the script still needs access to the repo.  
Can you send me the GitHub token again? I think the one I had expired.  

Alice:  
Sure, here it is: [attachment: key.txt]
Don’t paste it in Slack again though, lol.  

Bob:  
Got it, thanks! I’ll put it in the `.env` file.  

--- (later) ---

Bob:  
By the way, I pushed the hotfix to the repo, but the build pipeline still throws a permissions error.  
Are you sure that’s the right token?  

Alice:  
oops, sorry! I accidentally sent the old one. Use this token instead: ghp_ZyXwVuTsRqPoNmLkJiHgF9e8d7C6b5A4d3E1
That should work now.  

Bob:  
Perfect. Thanks, Alice. Build passed this time!  

--- END OF CHAT ---
```

Essentially, Microsoft/Presidio has a comprehensive set of default PII detection capabilities. 
However, since GitHub PAT (classic token) is not a default PII for that library,
So let's create a new configuration file named `recognizers_sample.yml` like below.
```yml
# recognizers_sample.yml
recognizers:
  - name: GitHub PAT (classic)
    supported_entity: GITHUB_TOKEN_CLASSIC
    supported_language: en
    patterns:
      - name: ghp_token
        regex: "\\bghp_[A-Za-z0-9]{36}\\b"
        score: 0.6
    context: [token, github, key]
```

And, by using a 16-character-long password(`1234567890ABCDEF` in this case), encrypt the detected PIIs using the library and get the output,
as well as the redacted version of the output (such as `example@inter.net` --> `<EMAIL_ADDRESS>`).
Using `--recognizer-yaml-config` command option, you can feed the additional PII matching configuration.
```sh
pii-crypt encrypt input.txt --also-redacted --output output.txt --key "1234567890ABCDEF" --recognizer-yaml-config recognizers_sample.yml
```

The output will appear as follows. Note that there is no guarantee that 100% of existing PII will be
successfully and perfectly detected and securely masked since the relying library (Presidio) is based on NLP,
regular expressions, and possibility stuff. But, generally, it won't be so bad.
```
# pii_sample_conversation.txt

[Chat log between two developers]

Alice (TkHzQebvgwInwxlzYDXFYSca1q0-NidrVEvYggUvQ3SWEr-me70Oa90coBxpUuuw):  
Hey KtgX7636kKEhpsO83RdS4VXKg5HtrAnw5RD83ut9iTc=, did you fix that deployment issue on the staging server?  

146wMNsdOmOnuJIP35J-oFltAdDW9n_G9Py0Zj86Lq0= (-yFjtTkF5o95RtBgfNa2PC4vZiV0ipBlSm1Nj7i6DsY=):  
Yeah, mostly. But the script still needs access to the repo.  
Can you send me the GitHub token again? I think the one I had expired.  

JK-UgD0aKb7LgOTKo-J9pNXm-5QySMBoPy_Gjrjw3is=:  
Sure, here it is: [attachment: key.txt]
Don’t paste it in Slack again though, lol.  

G-NECfHc6AhQYabwiu823UpXGmslGIqZ5Mnn3gRsmNo=:  
Got it, thanks! I’ll put it in the `.env` file.  

--- (later) ---

Ez80RO8x-282xck6ALuxJR6z_kTavBtfVzwl0GlaKN0=:  
By the way, I pushed the hotfix to the repo, but the build pipeline still throws a permissions error.  
Are you sure that’s the right token?  

7UsIsLgLS2Mgoz0Jyywfbg8SSqCXlSYuyYYmm3xKrLc=:  
oops, sorry! I accidentally sent the old one. Use this token instead: GJ9_EN3B5HUGL8wMVZob0tKEDzEHxC1tePoEsMcJoVqv6qwhwwulNb473Rv-L8eZFXb_DKa8Hw29p9UUGj4Ssg==
That should work now.  

qhhep5thZrnhC26aGcGSLFga998OyHukQGbRnUgkFrM=:  
Perfect. Thanks, hGTBflRAFsrmKEbS8b4tISDXxArepwc1e19GaaWHqmY=. Build passed this time!  

--- END OF CHAT ---
```

The entities will also be created. You also need to keep this entity file as well to decrypt the encrypted file accordingly.
```json
[                                                           
  {                                                         
    "start": 1223,                                          
    "end": 1267,                                            
    "entity_type": "PERSON",                                
    "text": "hGTBflRAFsrmKEbS8b4tISDXxArepwc1e19GaaWHqmY=", 
    "operator": "encrypt"                                   
  },                                                        
  # ...
]
```

Finally, the redacted output will be as follows.
```
# pii_sample_conversation.txt                                            
                                                                         
[Chat log between two developers]                                        
                                                                         
Alice (<EMAIL_ADDRESS>):                                                 
Hey <PERSON>, did you fix that deployment issue on the staging server?   
                                                                         
<PERSON> (<EMAIL_ADDRESS>):                                              
Yeah, mostly. But the script still needs access to the repo.             
Can you send me the GitHub token again? I think the one I had expired.   

...

<PERSON>:  
oops, sorry! I accidentally sent the old one. Use this token instead: <GITHUB_TOKEN_CLASSIC>
That should work now.  

...
```

For the given encrypted output, you can use the following command to decrypt the file. 
Please provide the password you used during encryption and the generated entity JSON file.
```
pii-crypt decrypt output.txt --key "1234567890ABCDEF" --output recovered.txt
```

