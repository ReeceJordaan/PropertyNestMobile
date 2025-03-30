import { Component, Renderer2 } from '@angular/core';
import { Router } from '@angular/router';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { FormGroup, FormBuilder, Validators } from '@angular/forms';

@Component({
  selector: 'app-tab4',
  templateUrl: './tab4.page.html',
  styleUrls: ['./tab4.page.scss'],
})
export class Tab4Page {
  loginForm!: FormGroup;
  emailInputId: string;
  passwordInputId: string;

  constructor(
    private formBuilder: FormBuilder,
    private http: HttpClient,
    private router: Router,
    private renderer: Renderer2
  ) {
    this.emailInputId = this.generateUniqueId();
    this.passwordInputId = this.generateUniqueId();
    this.initializeForm();
  }

  generateUniqueId(): string {
    return 'input-' + Math.random().toString(36).substr(2, 9);
  }

  initializeForm() {
    this.loginForm = this.formBuilder.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required]
    });
  }

  ionViewWillEnter() {
    // Reinitialize form if necessary
    this.initializeForm();
  }

  onSubmit() {
    if (this.loginForm.valid) {
      this.loginUser();
    }
  }

  loginUser() {
    const formData = {
      type: 'Login',
      email: this.loginForm.get('email')?.value,
      password: this.loginForm.get('password')?.value
    };

    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Basic ${btoa("u23547104:6F6FdO7ebFHiyZ00")}`
    });

    this.http.post('https://wheatley.cs.up.ac.za/u23547104/api.php', JSON.stringify(formData), { headers })
      .subscribe(
        (response: any) => {
          localStorage.setItem('apikey', response.data.apikey);
          localStorage.setItem('name', response.data.name);
          this.router.navigate(['/tabs/tab1']);
          this.renderer.setStyle(document.querySelector('.loginError'), 'display', 'none');
        },
        (error) => {
          this.renderer.setStyle(document.querySelector('.loginError'), 'display', 'block');
        }
      );
  }
}