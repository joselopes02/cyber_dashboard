// static/js/script.js

// Wait for the DOM to load before attaching events.
document.addEventListener('DOMContentLoaded', function() {
    // Attach keyup event to the search input to trigger search on Enter key press.
    var searchInput = document.getElementById('search');
    if (searchInput) {
      searchInput.addEventListener('keyup', function(event) {
        if (event.keyCode === 13) {  // Enter key
          doSearch();
        }
      });
    }
  });
  
  // Function to perform search by redirecting with query parameters.
  function doSearch() {
    var searchValue = document.getElementById('search').value;
    // Reload the current path with the search query parameter.
    window.location.href = window.location.pathname + '?search=' + encodeURIComponent(searchValue);
  }
  