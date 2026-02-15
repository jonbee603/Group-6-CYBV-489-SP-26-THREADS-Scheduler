@echo off

set "testPrefix=SchedulerTest"
set "testNumbers=00 01 02 03 04 05 06 07 08 09 10 11 12 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31"

set "logFile=SchedulerTests.log"

echo Running Scheduler Tests > %logFile%
echo ======================= >> %logFile%
echo. >> %logFile%

for %%a in (%testNumbers%) do (
    echo Running %testPrefix%%%a... >> %logFile%
    %testPrefix%%%a >> %logFile% 2>&1
    echo. >> %logFile%
)

echo All tests completed. >> %logFile%