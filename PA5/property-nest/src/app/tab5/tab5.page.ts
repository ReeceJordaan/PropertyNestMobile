import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { ToastController } from '@ionic/angular';

@Component({
  selector: 'app-tab5',
  templateUrl: 'tab5.page.html',
  styleUrls: ['tab5.page.scss']
})
export class Tab5Page {

  isLoading: boolean = true;
  hasAgents: boolean = false;
  hasNoAgents: boolean = false;
  agentInfoJSON: any[] = [];

  constructor(private http: HttpClient, private toastController: ToastController) {}

  ionViewWillEnter() {
    this.loadAgents();
  }

  loadAgents() {
    if (!localStorage.getItem('apikey')) {
      this.hideAllContent();
    } else {
      this.showLoading();
      this.fetchAgents();
    }
  }

  fetchAgents() {
    const text = {
      studentnum: "u23547104",
      apikey: "45ef79b2fde631bc3dc11a0c2a3a3ba2",
      type: "GetAllAgents",
      limit: 10
    };

    this.http.post<any>("https://wheatley.cs.up.ac.za/api/", text, {
      headers: {
        'Content-Type': 'application/json'
      }
    }).subscribe(
      response => {
        this.agentInfoJSON = response.data;
        this.fetchAgentLogos();
        this.hideLoading();
      },
      error => {
        console.error('Error fetching agents:', error);
        this.createToast('Error fetching agents.');
        this.hideLoading();
      }
    );
  }

  fetchAgentLogos() {
    for (let i = 0; i < this.agentInfoJSON.length; i++) {
      const agentName = this.agentInfoJSON[i].name;
      
      this.http.get<any>(`https://wheatley.cs.up.ac.za/api/getimage?agency=${agentName}`).subscribe(
        response => {
          if (response && response.data) {
            this.agentInfoJSON[i].logo = response.data;
          }
          this.populateAgents();
        },
        error => {
          console.error(`Error fetching logo for ${agentName}:`, error);
        }
      );
    }
  }

  populateAgents() {
    if (this.agentInfoJSON.length === 0) {
      this.hideAllContent();
    } else {
      this.hasAgents = true;
    }
  }

  private hideAllContent() {
    this.isLoading = false;
    this.hasAgents = false;
    this.hasNoAgents = true;
  }

  private showLoading() {
    this.isLoading = true;
    this.hasAgents = false;
    this.hasNoAgents = false;
  }

  private hideLoading() {
    this.isLoading = false;
    this.hasAgents = true;
    this.hasNoAgents = false;
  }

  async createToast(message: string) {
    const toast = await this.toastController.create({
      message: message,
      duration: 2000
    });
    
    toast.present();
  }

  handleRefresh(event: any) {
    this.loadAgents();
    event.target.complete();
    this.createToast('Agents refreshed successfully!');
  }
}
