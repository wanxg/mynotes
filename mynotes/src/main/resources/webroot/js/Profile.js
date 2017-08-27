var login = new Vue({
  el: '#profile-page',
  data: {
	  message: '',
	  pwd_update_failed: false,
	  pwd_update_success: false,
	  profile_update_failed: false,
	  profile_update_success: false,
	  no_local_account: true,
	  signup_success: false,
	  signup_failed: false
  },

  methods: {

	  updatePassword: function(){
		  
		  console.log("update password button clicked");
		  
		  var oldPassword = document.getElementById("old_password");
		  var newPassword = document.getElementById("new_password");
		  var confirmPassword = document.getElementById("confirm_password");
		  var pwd_update_failed_div = document.getElementById("pwd_update_failed_div");
		  var pwd_update_success_div = document.getElementById("pwd_update_success_div");
		  var update_pwd_form = document.getElementById("update_pwd_form");
 		
		  axios.post('/account', {
			  
			  old_password : oldPassword.value,
			  new_password : newPassword.value,
			  
		  })
		  .then(response => {
			  
			  console.log(response.data);
			  this.pwd_update_failed = false;
			  this.pwd_update_success = true;
			  this.message = 'Your password has been updated.';
			  $('#pwd_update_success_div').show();
			  oldPassword.value='';
			  newPassword.value='';
			  confirmPassword.value='';
			
		  })
		  .catch(error => {
			
			  if(error.response.status == '401'){
				  console.log("Session expired, please log in again.");
				  window.location.href = '/';
				  return;
			  }
			  console.log("Update failed due to invalid old password.");
			  console.log(error);
			  this.pwd_update_success = false;
			  this.pwd_update_failed = true;
			  this.message = 'Old password invalid.';
			  $('#pwd_update_failed_div').show();
		  }); 
		
	  },
	  
	  updateProfile: function(){
		  
		  console.log("update profile button clicked");
		  
		  var user_name = document.getElementById("username");
		  var first_name = document.getElementById("firstname");
		  var last_name = document.getElementById("lastname");
		  var _gender = 'unknown';
		  
		  var radios = document.getElementsByName('gender');
		  
		  for (var i = 0, length = radios.length; i < length; i++) {
			    if (radios[i].checked) {
			        _gender = radios[i].value;
			        break;
			    }
		  }
		  
		  console.log(_gender);
		  
		  var profile_update_failed_div = document.getElementById("profile_update_failed_div");
		  var profile_update_success_div = document.getElementById("profile_update_success_div");
		  var update_profile_form = document.getElementById("update_profile_form");
 		
		  axios.post('/profile', {
			  
			  username : user_name.value,
			  firstname : first_name.value,
			  lastname : last_name.value,
			  gender : _gender,
			  action : 'update'
			  
		  })
		  .then(response => {
			  
			  console.log(response.data);
			  this.profile_update_failed = false;
			  this.profile_update_success = true;
			  this.message = 'Your profile has been updated.';
			  $('#profile_update_success_div').show();
			  
			
		  })
		  .catch(error => {
			
			  if(error.response.status == '401'){
				  console.log("Session expired, please log in again.");
				  window.location.href = '/';
				  return;
			  }
			  console.log("Update failed: " + error.response.status);
			  console.log(error.response);
			  this.profile_update_failed = true;
			  this.profile_update_success = false;
			  $('#profile_update_failed_div').show();
		  }); 
		
	  },
	  
	  signup: function(){
		  
		  console.log("signup clicked");
		  
		  var user_name = document.getElementById("user_name");
		  var signup_email = document.getElementById("signup_email");
		  var signup_password = document.getElementById("signup_password");
		  var signup_success_div = document.getElementById("signup_success_div");
		  var signup_form = document.getElementById("signup_form");
		  var signup_button = document.getElementById("signup_button");
		  
		  axios.post('/signup', {
			  
			  username : user_name.value,
			  email : signup_email.value,
			  password : signup_password.value,
			  isProfileCreated : true
			  
		  })
		  .then(response => {
			
			  console.log(response);
			  this.no_local_account = false;
			  this.signup_success = true;
			  this.signup_failed = false;
			  this.message = 'Local account has been created.';
			  $('#signup_success_div').show();
			  signup_button.disabled = true;
			
		  })
		  .catch(error => {
			
			  if(error.response.status == '401'){
				  console.log("Session expired, please log in again.");
				  window.location.href = '/';
				  return;
			  }
			  console.log("Signup failed.");
			  console.log(error);
			
			  this.signup_failed = true;
			  this.signup_success = false;
			  this.message = 'This email is already registered.';
			  $('#signup_failed_div').show();
		  }); 
		  
	  }
	  
  },
  
  mounted: function (){
	  
	  //Not working
	  window.setTimeout(function() {
		  $(".alert-success").fadeTo(500, 0).slideUp(500, function(){$(this).remove();});
	  }, 5000);
	  
	  
	  $(function(){
		  console.log("Attached hide method to alert.");
		  $(document).on("click", '[data-hide]', function(){
		    	$(this).closest("." + $(this).attr("data-hide")).hide();
		    });
	  });
	  
	  var newPassword = document.getElementById("new_password");
	  var confirmPassword = document.getElementById("confirm_password");
	  
	  var validatePassword = function(){
		 
		  if (newPassword.value != confirmPassword.value) {
			  confirmPassword.setCustomValidity("Passwords don't match.");
			  
		  } else {
			  
			  confirmPassword.setCustomValidity('');
		  }
	  }
	  
	  newPassword.onchange = validatePassword;
	  confirmPassword.onkeyup = validatePassword;
	  
  }

});