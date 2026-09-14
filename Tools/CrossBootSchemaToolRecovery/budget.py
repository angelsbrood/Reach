"""Costs from the measured S105 committed phase trace, before originals exist."""
import base64

def protocol_budget(probe, rows, lane):
    rows=[x for x in rows if x['operation']!='ready-restore']
    assert rows[0]['operation']=='prepare' and rows[-1]['operation']=='ready-deliver'
    cut=next(i for i,x in enumerate(rows) if x['progress']==probe['cutProbe'])
    guided=next(i for i,x in enumerate(rows) if x['progress']==probe['cutGuided'])
    ready=next(i for i,x in enumerate(rows) if x['progress']['phase']=='finalReady')
    route=next(i for i,x in enumerate(rows) if x['progress']['phase']=='routeReady')
    assert rows[cut]['progress']['probe']['rawTokens']>0 and rows[cut]['progress']['proseDelivered']==0
    assert all(not base64.b64decode(x['eventBytes']) or base64.b64decode(x['eventBytes'])==b'[]' for x in rows[:route+1])
    g=rows[guided]['progress']
    assert g['guided']['consumedTokens']>0 and g['guided']['pendingTokens']>0 and base64.b64decode(g['whole'])
    assert probe['cutGuidedPublicEvents']>0 if lane=='normal' else probe['cutGuidedPublicEvents']==0
    def owner_actions(start,end,original=False):
        actions=2 if original else 1;i=1 if original else start+1
        while i<=end:
            actions+=1;phase=rows[i-1]['progress']['phase']
            for _ in range(2 if phase in ['probe','guided'] else 1):
                current=rows[i]['progress']['phase'];i+=1
                if current!=phase or i>end:break
        return actions
    owners=dict(probeCut=owner_actions(0,cut,True),resumeProbe=owner_actions(cut,guided),resumeGuided=owner_actions(guided,ready),
        freshReady=owner_actions(ready,len(rows)-1),terminal=2,duplicate=2,reference=owner_actions(0,len(rows)-1,True))
    faults=dict(routeCut=owner_actions(0,route,True),delayedNextPass=2) if lane=='normal' else {}
    certificates=dict(primary=2+sum(v for k,v in owners.items() if k!='reference'),reference=2+owners['reference'])
    if faults:certificates['faults']=2+sum(faults.values())
    ownerMax=max([*owners.values(),*faults.values()]);nonceMax=max(certificates.values())
    assert ownerMax<=62 and nonceMax<=120,(owners,faults,certificates)
    return dict(ownerActions=owners,faultOwnerActions=faults,certificates=certificates,ownerCeiling=64,
        minimumOwnerHeadroom=64-ownerMax,nonceCeiling=128,minimumNonceHeadroom=128-nonceMax,
        registrationsPerWitness=2,registrationCeiling=16,
        derivation='Measured committed trace; reopen, prepare, grouped advances, both positive cuts, ready delivery, terminal replay and duplicate counted. Admission and acceptance add two. Each serial pair has its own original witness; reference has one uninterrupted generation owner.')
