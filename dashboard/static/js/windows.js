/* highlight functionnality */
$('#processCacheTable').on('click', 'tbody tr', function(event) {
  var table = $(this);

  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});



$('#processTreeTable').on('click', 'tbody tr', function(event) {
  var table = $(this);

  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});

$('#processScanTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});

$('#processEnvTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});

$('#processCmdTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});

$('#processPrivilegesTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});


$('#processNetworkTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});


$('#TimelineTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});


$('#FileScanTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});

$('#IOCTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});

$('#processHashTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});


$('#processCacheTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});

$('#processLsaTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});

$('#processNetworkStatTable').on('click', 'tbody tr', function(event) {
  var table = $(this);
  if (table.hasClass("highlight")){
    table.removeClass("highlight");
  }
  else{
    table.addClass("highlight");
  }
});

$(document).ready(function(){
  $('.container').show();
  $('.container-fluid').show();
  $('.plugin').hide();
  $('.Case').show();
  $('.spinner-main').hide();
  $('.toast-other').toast('show');

  $('#main').show();
  $('#loading').hide();

  /* Search bar Functionnality for each plugin */
  $("#searchProcess").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#process tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //NetStat Search funtion
  $("#searchNetworkStat").on("keyup", function() {
      var value = $(this).val().toLowerCase();
      $("#netstat tr").filter(function() {
        $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
      });
    });

  //Malfind Search function

  $("#searchMalfind").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#malfind-btn button").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //TimeLine SearchBar
  $("#searchTimeline").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#TimelineTab tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) !== -1)
    })
  });

  //CmdLine SearchBar

  $("#searchCmdLine").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#cmdline tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //Network SearchBar

  $("#searchNetwork").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#network tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //ProcessScan SearchBar

  $("#searchProcessScan").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#processScan tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });



  //Process Privileges SearchBar

  $("#searchPriv").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#processPriv tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //Process Env SearchBar

  $("#searchEnv").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#processEnv tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //FileScan SearchBar

  $("#searchFileScan").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#FileScanTab tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //IOC SearchBar

  $("#searchIOC").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#IOCTab tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  /* Sidebar user interaction management : Display the resquested plugin and hide the previous one */

  $("#PsScanLink").on("click", function(){
    $('.plugin').hide();
    $('.PsScan').show();
  });
  $("#PsListLink").on("click", function(){
    $('.plugin').hide();
    $('.PsList').show();
  });
  $("#PrivsLink").on("click", function(){
    $('.plugin').hide();
    $('.Privs').show();
  });

  $("#PsTreeLink").on("click", function(){
    $('.plugin').hide();
    $('.PsTree').show();
  });

  $("#CmdLineLink").on("click", function(){
    $('.plugin').hide();
    $('.CmdLine').show();
  });

  $("#EnvarsLink").on("click", function(){
    $('.plugin').hide();
    $('.Envars').show();
  });

  $("#NetGraphLink").on("click", function(){
    $('.plugin').hide();
    $('.NetGraph').show();
  });


  $("#NetScanLink").on("click", function(){
    $('.plugin').hide();
    $('.NetScan').show();
  });


  $("#NetStatLink").on("click", function(){
    $('.plugin').hide();
    $('.NetStat').show();
  });

  $("#HashDumpLink").on("click", function(){
    $('.plugin').hide();
    $('.HashDump').show();
  });


  $("#LsaDumpLink").on("click", function(){
    $('.plugin').hide();
    $('.LsaDump').show();
  });

  $("#CacheDumpLink").on("click", function(){
    $('.plugin').hide();
    $('.CacheDump').show();
  });

  $("#SkeletonLink").on("click", function(){
    $('.plugin').hide();
    $('.SkeletonKeyCheck').show();
  });

  $("#HiveListLink").on("click", function(){
    $('.plugin').hide();
    $('.HiveList').show();
  });

  $("#TimelineLink").on("click", function(){
    $('.plugin').hide();
    $('.Timeline').show();
  });

  $("#IOCLink").on("click", function(){
    $('.plugin').hide();
    $('.IOC').show();
  });

  $("#MalfindLink").on("click", function(){
    $('.plugin').hide();
    $('.Malfind').show();
  });

  $("#FileScanLink").on("click", function(){
    $('.plugin').hide();
    $('.FileScan').show();
  });

  $("#CaseLink").on("click", function(){
    $('.plugin').hide();
    $('.Case').show();
  });

  $("#DetectionLink").on("click", function(){
    $('.plugin').hide();
    $('.Detection').show();
  });
});

function Virustotal(pk,url) {
  const csrf = document.getElementsByName('csrfmiddlewaretoken');
  const fd = new FormData();
  fd.append('csrfmiddlewaretoken', csrf[0].value);
  fd.append('id', pk);
  $.ajax({
    type: 'POST',
    url: url,
    enctype: 'multipart/form-data',
    data: fd,
    beforeSend: function () {
      $('#proc-message').html("Your Virustotal request was taken into account");
      $('.toast-proc').toast('show');
    },
    success: function (response) {
      console.log(response['message']);
      console.log(response['url']);
      
      switch (response['message']['data']['type']) {
        case "analysis":
          $('#proc-message').html("Virustotal is still processing your file");
          $('.toast-proc').toast('show');
          break;
        case "file":
          document.querySelector('#vt-augment-container').src = response['url'];
          $("#showVirustotal").modal("show");
          break;
        default:
          break;
      }
    },
    error: function (error) {
      console.log(error);
      $('#proc-error-message').html("Virustotal analysis error");
      $('.toast-proc-error').toast('show');
    },
    cache: false,
    contentType: false,
    processData: false
  });
}

function ClamAV(id,model,url) {
  const csrf = document.getElementsByName('csrfmiddlewaretoken');
  const fd = new FormData();
  fd.append('csrfmiddlewaretoken', csrf[0].value);
  fd.append('id', id);
  fd.append('model', model);
  $.ajax({
    type: 'POST',
    url: url,
    enctype: 'multipart/form-data',
    data: fd,
    beforeSend: function () {
      $('.spinner-main').show();
      $('#proc-message').html("Your ClamAV request was taken into account");
      $('.toast-proc').toast('show');
    },
    success: function (response) {
      console.log(response['message']);
      if(response['message'][0]){
        document.querySelector('#clamAVModalContent').style.color = "red"
        document.querySelector('#clamAVModalContent').innerHTML = response['message'][1];
      }
      else{
        document.querySelector('#clamAVModalContent').innerHTML = "Nothing detected";
        document.querySelector('#clamAVModalContent').style.color = "black"
      }
      $("#showClamAVModal").modal("show");
      $('.spinner-main').hide();
    },
    error: function (error) {
      console.log(error);
      $('#proc-error-message').html("ClamAV analysis error");
      $('.toast-proc-error').toast('show');
      $('.spinner-main').hide();
    },
    cache: false,
    contentType: false,
    processData: false
  });
}