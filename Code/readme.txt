Project:ORWL
Description:It includes the applets which associate the KeyFOB with ORWL device. Later on successful authentication of KeyFOB with ORWL, it unlocks the ORWL device.
Prerequisites:SkySim developer suite to build the project

Process:Following are the steps to load the project and create the cap files required for execution of applet.
1. Open SkySim developer suite tool
2. Import the ORWL project available in GIT
	a. Select File option available in menu bar
	b. Click on Import option available under File menu
	c. Double click on “Existing Projects into Workspace” available under General
	d. Click on “Browse” option available with select root directory
	e. Select the ORWL project downloaded from GIT and click OK
	f. Click on Finish button
3. Clean and build the ORWL project
	a. Select Project option available in menu bar
	b. Click on Clean option available under Project menu
	c. Click on checkbox of ORWL project
	d. Click on the checkbox “Start a build immediately”
	4. The cap files are generated and available in the ORWL project folder
		ORWL -> bin -> com -> orwlinterface -> javacard -> orwlinterface.cap
		ORWL -> bin -> com -> orwlkeypair -> javacard -> orwlkeypair.cap
		ORWL -> bin -> com -> orwlbleseed -> javacard -> orwlbleseed.cap
5. These generated cap files are used to load the applets in KeyFOB using Jload tool