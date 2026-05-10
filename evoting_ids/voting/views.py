from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.db.models import F
from django.contrib import messages
from .models import Election, Candidate, Vote


def election_list(request):
      elections = Election.objects.filter(is_active=True)
      return render(request, 'voting/election_list.html', {'elections': elections})


@login_required
def cast_vote(request, election_id):
      election = get_object_or_404(Election, pk=election_id, is_active=True)

      if Vote.objects.filter(voter=request.user, election=election).exists():
          messages.error(request, 'You have already voted in this election.')
          return redirect('election_list')

      if request.method == 'POST':
          candidate_id = request.POST.get('candidate')
          candidate = get_object_or_404(Candidate, pk=candidate_id, election=election)

          Vote.objects.create(
              voter=request.user,
              election=election,
              candidate=candidate,
              ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
          )
          Candidate.objects.filter(pk=candidate.pk).update(vote_count=F('vote_count') + 1)

          messages.success(request, 'Your vote has been cast.')
          return redirect('view_results', election_id=election.pk)

      candidates = election.candidates.all()
      return render(request, 'voting/vote.html', {'election': election, 'candidates': candidates})


def view_results(request, election_id):
      election = get_object_or_404(Election, pk=election_id)
      candidates = election.candidates.order_by('-vote_count')
      return render(request, 'voting/results.html', {'election': election, 'candidates': candidates})
