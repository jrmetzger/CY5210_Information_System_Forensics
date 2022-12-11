$DIR = "../TOOLS"
$CASESTUDY = "CaseStudy03"

# SHELLBAG ANALYSIS
"${DIR}/SBECmd/SBECmd.exe -d ${CASESTUDY}/CaseFolder --csv ${CASESTUDY}/CaseFolder/ShellbagAnalysis"

# PREFETCH ANALYSIS
"${DIR}/PECmd/PECmd.exe -d  ${CASESTUDY}/CaseFolder/Prefetch --csv ${CASESTUDY}/CaseFolder/PrefetchAnalysis"

# LINK ANALYSIS
"${DIR}/LECmd/LECmd.exe -d ${CASESTUDY}/CaseFolder/Recent --csv ${CASESTUDY}/CaseFolder/LinkAnalysis"

# JUMP ANALYSIS
"${DIR}/JLECmd/JLECmd.exe -d ${CASESTUDY}/CaseFolder/Recent --csv ${CASESTUDY}/CaseFolder/JumpAnalysis"
