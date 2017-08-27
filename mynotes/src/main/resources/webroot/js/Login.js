var login = new Vue({
  el: '#login-page',
  data: {
	  message: '',
	  login_failed: false,
	  signup_failed: false
  },

  methods: {

	  login: function(){
		  
		  console.log("login clicked");
		  
		  var email = document.getElementById("login_email");
		  var password = document.getElementById("login_password");
		  var rememberMe = document.getElementById("remember_me");
		  var login_failed_div = document.getElementById("login_failed_div");
		  var login_form = document.getElementById("login_form");
 		
		  axios.post('/login', {
			  
			  login_email : email.value,
			  login_password : password.value,
			  remember_me : rememberMe.checked,
			  
		  })
		  .then(response => {
			
			  console.log(response);
			  //login_form.submit();
			  window.location.href = '/'
			
		  })
		  .catch(error => {
			
			  console.log("Login failed due to invalid email or password.");
			  console.log(error);
			
			  this.login_failed = true;
			  this.message = 'Invalid email address or password.';
			  $('#login_failed_div').show();
		  }); 
		
	  },
	  
	  
	  signup: function(){
		  
		  console.log("signup clicked");
		  
		  var user_name = document.getElementById("user_name");
		  var signup_email = document.getElementById("signup_email");
		  var signup_password = document.getElementById("signup_password");
		  var signup_failed_div = document.getElementById("signup_failed_div");
		  var signup_form = document.getElementById("signup_form");
		  
		  axios.post('/signup', {
			  
			  username : user_name.value,
			  email : signup_email.value,
			  password : signup_password.value,
			  
		  })
		  .then(response => {
			
			  console.log(response);
			  //signup_form.submit();
			  window.location.href = '/'
			
		  })
		  .catch(error => {
			
			  console.log("Signup failed.");
			  console.log(error);
			
			  this.signup_failed = true;
			  this.message = 'This email is already registered.';
			  $('#signup_failed_div').show();
		  }); 
		  
	  }
	  
  },
  
  mounted: function (){
	  
	  $(function(){
		  console.log("Attached hide method to alert.");
		  $(document).on("click", '[data-hide]', function(){
		    	$(this).closest("." + $(this).attr("data-hide")).hide();
		    });
	  });
	  
	  var email = document.getElementById("signup_email");
	  var reemail = document.getElementById("signup_reemail");

	  function validateEmail() {
		  if (email.value != reemail.value) {
			
			 reemail.setCustomValidity("Emails don't match.");
		  } else {
			reemail.setCustomValidity('');
		  }
	  }

	  email.onchange = validateEmail;
	  reemail.onkeyup = validateEmail;
	  
  }
  

});