# sAnDbOx-Evasion
I have been diving into some of the PEB bitfields. During my research I discovered isAppContainer and wanted to share my thoughts.

While diving into the PEB for my debugger I noticed a bitfield labled isAppContainer. After some research I learned that this flag
is set to help Windows label containerized apps. The benefit of running a program in a container is it really isnt seen as a major
red flag even if doing some suspicous actions. Because of the lessoned restriction by EDRs/AV this helps to lower the detection ratio
by faking a app that is in a sandbox, when it really isnt.

The reason this works is because some EDRs like VT will trigger this flag. Just like IsDebuggerPresent(), this bitfield can
be abused to avoid sandboxes. A possible action to take would be to terminate the process if the flag is set to 1 or even a decoy 
function. 

see ya 

-Sleepy
