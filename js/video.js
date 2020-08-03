$(() => {
  
  $("#video1").click(() => {
    $("#ekavideo").removeClass("piilo");
    $("#lisaavideoita").addClass("piilo");
    $("#ekavideo").attr('src', 'https://www.youtube.com/embed/GG6fVaFrXz4');
  });

  $("#video2").click(() => {
    $("#ekavideo").removeClass("piilo");
    $("#lisaavideoita").addClass("piilo");
    $("#ekavideo").attr('src', 'https://www.youtube.com/embed/IRt3qq-klD4');
    
  });
  
  $("#video3").click(() => {
    $("#ekavideo").addClass("piilo");
    $("#lisaavideoita").removeClass("piilo");
  });



});