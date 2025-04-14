Instructions to run:

1.	Start both VMs using: 
	a.	VBoxManage startvm CS528_vm1 --type headless [11259]
	b.	VBoxManage startvm cs528_vm2 --type headless (case sensitive cs528_vm2) [11260]
2.	SSH into the machines
	a.	ssh -p 11259 cs528user@localhost (other is 11260)
3.	Run the VPN:
	a.	cd /submission
	b.	gcc -o simpletun simpletun.c -lssl -lcrypt on both machines
	c.	No changes in the default execution command, you can find it in the report.
4.	Setup the tunnels:
	a.	sudo ./config_vm# {replace # by 1 or 2 as you need.}
5.	Play around, have a good day!

Note: I have used mc20.cs.purdue.edu as VBoxManage was unusable in mc19. 
