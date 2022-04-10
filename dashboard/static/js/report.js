
    function ReportProcessScan(){
      document.getElementById('searchProcessScan').value = "";
      $('#searchProcessScan').keyup();
      var TheadProcessScan = $('table.processcan > tbody > tr.highlight').clone();
      var TrProcessScan = $('table.processcan > thead').clone();
      $('#report_table_process_scan').append(TheadProcessScan);
      $('#report_table_process_scan').append(TrProcessScan);
    }

    function ReportProcessCmdLine(){
      document.getElementById('searchCmdLine').value = "";
      $('#searchCmdLine').keyup();
      var TheadProcessCmdline = $('table.processcmdline > tbody > tr.highlight').clone();
      var TrProcessCmdline = $('table.processcmdline > thead').clone();
      $('#report_table_process_cmdline').append(TheadProcessCmdline);
      $('#report_table_process_cmdline').append(TrProcessCmdline);
    }

    function ReportProcessPriv(){
      document.getElementById('searchPriv').value = "";
      $('#searchPriv').keyup();
      var TheadProcessPriv = $('table.processpriv > tbody > tr.highlight').clone();
      var TrProcessPriv = $('table.processpriv > thead').clone();
      $('#report_table_process_priv').append(TheadProcessPriv);
      $('#report_table_process_priv').append(TrProcessPriv);
    }

    function ReportProcessEnv(){
      document.getElementById('searchEnv').value = "";
      $('#searchEnv').keyup();
      var TheadProcessEnv = $('table.processenv > tbody > tr.highlight').clone();
      var TrProcessEnv = $('table.processenv > thead').clone();
      $('#report_table_process_env').append(TheadProcessEnv);
      $('#report_table_process_env').append(TrProcessEnv);
    }

    function ReportNetscan(){
      document.getElementById('searchNetwork').value = "";
      $('#searchNetwork').keyup();
      var TheadNetscan = $('table.netscan > tbody > tr.highlight').clone();
      var TrNetscan = $('table.netscan > thead').clone();
      $('#report_table_process_net').append(TheadNetscan);
      $('#report_table_process_net').append(TrNetscan);
    }

    function ReportNetstat(){
      document.getElementById('searchNetworkStat').value = "";
      $('#searchNetwork').keyup();
      var TheadNetstat = $('table.netstat > tbody > tr.highlight').clone();
      var TrNetstat = $('table.netstat > thead').clone();
      $('#report_table_process_netstat').append(TheadNetstat);
      $('#report_table_process_netstat').append(TrNetstat);
    }

    function ReportTimeline(){
      document.getElementById('searchTimeline').value = "";
      $('#searchTimeline').keyup();
      var TheadTimeline = $('table.timeline > tbody > tr.highlight').clone();
      var TrTimeline = $('table.timeline > thead').clone();
      $('#report_table_timeline').append(TheadTimeline);
      $('#report_table_timeline').append(TrTimeline);
    }

    function ReportHashdump(){
      var TheadHashDump = $('table.hashdump > tbody > tr.highlight').clone();
      var TrTimeHashDump = $('table.hashdump > thead').clone();
      $('#report_table_hashdump').append(TheadHashDump);
      $('#report_table_hashdump').append(TrTimeHashDump);
    }

    function ReportSkeleton(){
      var TheadSkeleton = $('table.skeleton > tbody > tr.highlight').clone();
      var TrTimeSkeleton = $('table.skeleton > thead').clone();
      $('#report_table_skeleton').append(TheadSkeleton);
      $('#report_table_skeleton').append(TrTimeSkeleton);
    }


    function ReportLsadump(){
      var TheadLsaDump = $('table.lsadump > tbody > tr.highlight').clone();
      var TrTimeLsaDump = $('table.lsadump > thead').clone();
      $('#report_table_lsadump').append(TheadLsaDump);
      $('#report_table_lsadump').append(TrTimeLsaDump);
    }

    function ReportIOC(){
      document.getElementById('searchIOC').value = "";
      $('#searchIOC').keyup();
      var TheadIOC = $('table.ioc > tbody > tr.highlight').clone();
      var TrIOC = $('table.ioc > thead').clone();
      $('#report_table_ioc').append(TheadIOC);
      $('#report_table_ioc').append(TrIOC);
    }

    function ReportFileScan(){
      document.getElementById('searchFileScan').value = "";
      $('#searchFileScan').keyup();
      var TheadFileS = $('table.filescan > tbody > tr.highlight').clone();
      var TrFileS = $('table.filescan > thead').clone();
      $('#report_table_filescan').append(TheadFileS);
      $('#report_table_filescan').append(TrFileS);
    }

    function ReportProcessTree(){
      document.getElementById('searchProcess').value = "";
      $('#searchProcess').keyup();
      var TheadProcess = $('table.processtree > tbody > tr.highlight').clone();
      var TrFileProcess = $('table.processtree > thead').clone();
      $('#report_table_processtree').append(TheadProcess);
      $('#report_table_processtree').append(TrFileProcess);
    }

    function ReportCachedump(){
      var TheadCacheDump = $('table.cachedump > tbody > tr.highlight').clone();
      var TrTimeCacheDump = $('table.cachedump > thead').clone();
      $('#report_table_cachedump').append(TheadCacheDump);
      $('#report_table_cachedump').append(TrTimeCacheDump);
    }



    function GenerateReport(case_name,os,description,filename){
      const { jsPDF } = window.jspdf;
      const doc = new jsPDF();
      doc.setFont("helvetica");
      doc.setFontSize(18);
      doc.text("Memory Investigation Report", 10, 10);
      doc.setFontSize(10);
      doc.text("Case Name : " + case_name, 10, 20);
      doc.text("OS : " + os, 10, 25);
      doc.text("Description : " + description, 10, 30);
      doc.text("The purpose of this report is to provide findings from "+ filename + " evidence.", 10, 50);
      doc.setFontSize(15);
      doc.text("Process Scan Artifacts :",10,60)
      doc.setFontSize(10);
      ReportProcessScan();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);

      doc.autoTable({
        tableWidth: 'wrap',
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8 },
        margin: { top: 65 },
        html: '#report_table_process_scan',
      });

      doc.setFontSize(15);
      doc.text("Process Tree Artifacts:",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportProcessTree();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_processtree',
      });


      doc.setFontSize(15);
      doc.text("Process Command Line Artifacts :",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportProcessCmdLine();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_process_cmdline',
      });

      doc.setFontSize(15);
      doc.text("Process Privileges Artifacts :",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportProcessPriv();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_process_priv',
      });

      doc.setFontSize(15);
      doc.text("Process Environnement variables Artifacts :",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportProcessEnv();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_process_env',
      });

      doc.setFontSize(15);
      doc.text("Network Artifacts : netscan",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportNetscan();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_process_net',
      });

      doc.setFontSize(15);
      doc.text("Network artifacts : netstat",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportNetstat();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_process_netstat',
      });

      doc.setFontSize(15);
      doc.text("Cryptography Artifacts : Hashdump",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportHashdump();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_hashdump',
      });

      doc.setFontSize(15);
      doc.text("Cryptography Artifacts : Cachedump",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportCachedump();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_cachedump',
      });

      doc.setFontSize(15);
      doc.text("Cryptography Artifacts : Lsadump",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportLsadump();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_lsadump',
      });

      doc.setFontSize(15);
      doc.text("Malware Artifacts : Skeleton Key",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportLsadump();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_skeleton',
      });


      doc.setFontSize(15);
      doc.text("IOCs:",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportIOC();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_ioc',
      });

      doc.setFontSize(15);
      doc.text("FileScan Artifacts:",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportFileScan();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_filescan',
      });

      doc.setFontSize(15);
      doc.text("Other Artifacts :",10,doc.autoTable.previous.finalY + 10);
      doc.setFontSize(10);
      ReportTimeline();
      doc.setLineWidth(0.2);
      doc.line(10, 45, 200, 45);
      doc.autoTable({
        rowPageBreak: 'auto',
        styles: { cellPadding: 0.5, fontSize: 8},
        startY: doc.autoTable.previous.finalY + 15,
        html: '#report_table_timeline',
      });

      doc.save("report.pdf");
    }
