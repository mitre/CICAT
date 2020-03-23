python ..\generator\loaddata.py > loadstatus.out
python ..\generator\topology.py > topostatus.out
rem python cicat.py location > locRep.out
rem python cicat.py scenario > scenRep.out
rem python cicat.py actor > actorRep.out
rem python cicat.py capability > capRep.out
python ..\generator\actorGEN.py > actgen.out
python ..\generator\TACSequence.py > tacseq.out
rem python TTPGEN.py > tpgen.out
python ..\generator\TTPFilter.py > tpfilter.out
python ..\generator\ffactory.py > ffact.out








